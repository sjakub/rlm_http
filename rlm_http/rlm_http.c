/*
 * rlm_http.c
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2012  The FreeRADIUS server project
 * Copyright 2012       Jakub Schmidtke <sjakub@gmail.com>
 */

//
// Config example:
//
// http {
//         host         = example.com
//         port         = 80
//         timeout      = 5
//         url          = /url/to/use/
//         method       = POST
//         payload      = '{ "json_key": [ "var1", "var2", "var3" ] }'
//         payload_type = 'application/json'
// }
//

#include <freeradius-devel/ident.h>
RCSID ( "$Id$" )

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#define HTTP_AUTH_TYPE        "HTTP"

#define DEFAULT_HOST          "127.0.0.1"
#define DEFAULT_PORT          80
#define DEFAULT_URL           "/"
#define DEFAULT_METHOD        "GET"
#define DEFAULT_TIMEOUT       5
#define DEFAULT_PAYLOAD       ""
#define DEFAULT_PAYLOAD_TYPE  ""

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define RD_LOG(fmt, ...)   RDEBUG ( "%s(): " fmt, __FUNCTION__, ## __VA_ARGS__)

#define D_LOG(fmt, ...)   radlog ( L_DBG, "%s(): " fmt, __FUNCTION__, ## __VA_ARGS__)
#define I_LOG(fmt, ...)   radlog ( L_INFO, "%s(): " fmt, __FUNCTION__, ## __VA_ARGS__)
#define E_LOG(fmt, ...)   radlog ( L_ERR, "%s(): " fmt, __FUNCTION__, ## __VA_ARGS__)

/*
 * A simple string-like structure
 */
struct string
{
    char * buffer;
    int mem_size;
    int data_size;
};

/*
 *  Define a structure for our module configuration.
 *
 *  These variables do not need to be in a structure, but it's
 *  a lot cleaner to do so, and a pointer to the structure can
 *  be used as the instance handle.
 */
typedef struct rlm_http_t
{
    int         port;
    int         timeout;
    uint32_t    host;
    char*       host_str;
    char*       url;
    char*       payload;
    char*       payload_type;
    char*       method;

    char*       req_header;
    struct sockaddr_in host_addr;
} rlm_http_t;

/*
 *  A mapping of configuration file names to internal variables.
 *
 *  Note that the string is dynamically allocated, so it MUST
 *  be freed.  When the configuration file parse re-reads the string,
 *  it free's the old one, and strdup's the new one, placing the pointer
 *  to the strdup'd string into 'config.string'.  This gets around
 *  buffer over-flows.
 */
static const CONF_PARSER module_config[] =
{
    { "timeout",      PW_TYPE_INTEGER,    offsetof ( rlm_http_t, timeout ),      NULL, STR ( DEFAULT_TIMEOUT ) },
    { "port",         PW_TYPE_INTEGER,    offsetof ( rlm_http_t, port ),         NULL, STR ( DEFAULT_PORT ) },
    { "host",         PW_TYPE_IPADDR,     offsetof ( rlm_http_t, host ),         NULL, DEFAULT_HOST },
    { "host",         PW_TYPE_STRING_PTR, offsetof ( rlm_http_t, host_str ),     NULL, DEFAULT_HOST },
    { "url",          PW_TYPE_STRING_PTR, offsetof ( rlm_http_t, url ),          NULL, DEFAULT_URL },
    { "method",       PW_TYPE_STRING_PTR, offsetof ( rlm_http_t, method ),       NULL, DEFAULT_METHOD },
    { "payload",      PW_TYPE_STRING_PTR, offsetof ( rlm_http_t, payload ),      NULL, DEFAULT_PAYLOAD },
    { "payload_type", PW_TYPE_STRING_PTR, offsetof ( rlm_http_t, payload_type ), NULL, DEFAULT_PAYLOAD_TYPE },

    { NULL, -1, 0, NULL, NULL }       /* end the list */
};

static void append_int ( struct string * str, int what );
static void append_str ( struct string * str, const char * what );
static void append_data ( struct string * str, const char * what, int what_len );
static char * get_attr_name ( int attr );
static char * base64_encode ( struct string * src );
static int http_do_request ( int sockfd, rlm_http_t * data, REQUEST * request );

/*
 *  Do any per-module initialization that is separate to each
 *  configured instance of the module.  e.g. set up connections
 *  to external databases, read configuration files, set up
 *  dictionary entries, etc.
 *
 *  If configuration information is given in the config section
 *  that must be referenced in later calls, store a handle to it
 *  in *instance otherwise put a null pointer there.
 */
static int http_instantiate ( CONF_SECTION *conf, void **instance )
{
    rlm_http_t *data;

    /*
     *  Set up a storage area for instance data
     */
    data = rad_malloc ( sizeof ( *data ) );

    if ( !data )
    {
        return -1;
    }

    memset ( data, 0, sizeof ( *data ) );

    /*
     *  If the configuration parameters can't be parsed, then
     *  fail.
     */
    if ( cf_section_parse ( conf, data, module_config ) < 0 )
    {
        free ( data );
        return -1;
    }

    if ( data->port < 1 )
    {
        E_LOG ( "Invalid port configured: %d; Changing to %d", data->port, DEFAULT_PORT );
        data->port = DEFAULT_PORT;
    }

    if ( data->timeout < 0 )
    {
        E_LOG ( "Invalid timeout configured: %d; Changing to %d", data->timeout, DEFAULT_TIMEOUT );
        data->timeout = DEFAULT_TIMEOUT;
    }

    int is_post = FALSE;

    if ( strcasecmp ( data->method, "post" ) == 0 )
    {
        is_post = TRUE;
    }
    else
    {
        if ( strcasecmp ( data->method, "get" ) != 0 )
        {
            E_LOG ( "Invalid method configured: '%s'; Using GET", data->method );

            // We don't need to actually change it, is_post will be FALSE anyway!
        }

        if ( strlen ( data->payload ) > 0 )
        {
            E_LOG ( "POST payload set, but GET method will be used; Payload will not be sent" );
            data->payload[0] = 0;
        }

        if ( strlen ( data->payload_type ) > 0 )
        {
            E_LOG ( "POST payload_type set, but GET method will be used; Payload type will not be sent" );
            data->payload_type[0] = 0;
        }
    }

    struct string str;

    memset ( &str, 0, sizeof ( struct string ) );

    append_str ( &str, is_post ? "POST " : "GET " );
    append_str ( &str, ( strlen ( data->url ) > 0 ) ? ( data->url ) : ( "/" ) );
    append_str ( &str, " HTTP/1.1\r\n" );
    append_str ( &str, "Host: " );
    append_str ( &str, data->host_str );

    if ( data->port != 80 )
    {
        append_str ( &str, ":" );
        append_int ( &str, data->port );
    }

    append_str ( &str, "\r\n" );

    if ( is_post )
    {
        append_str ( &str, "Content-Type: " );
        append_str ( &str, data->payload_type );
        append_str ( &str, "\r\nContent-Length: " );
        append_int ( &str, strlen ( data->payload ) );
        append_str ( &str, "\r\n" );
    }

    data->req_header = str.buffer;

    memset ( &str, 0, sizeof ( str ) );

    data->host_addr.sin_family = AF_INET;
    data->host_addr.sin_port = htons ( data->port & 0xFFFF );
    memcpy ( &data->host_addr.sin_addr.s_addr, &data->host, sizeof ( data->host ) );

    D_LOG ( "host: %s [%s]; port: %d; timeout: %d; url: '%s'; method: %s; headers: '%s'",
            data->host_str, inet_ntoa ( data->host_addr.sin_addr ),
            data->port, data->timeout, data->url, is_post ? "POST" : "GET", data->req_header );
    D_LOG ( "POST payload (%s): '%s'", data->payload_type, data->payload );

    *instance = data;

    return 0;
}

/*
 *  Only free memory we allocated.  The strings allocated via
 *  cf_section_parse() do not need to be freed.
 */
static int http_detach ( void* instance )
{
    rlm_http_t* data = instance;

    if ( data != NULL )
    {
        free ( data->req_header );
    }

    free ( data );

    return 0;
}

static int http_authorize ( void *instance, REQUEST *request )
{
    VALUE_PAIR *vp = NULL;
    int auth_type = FALSE;

    // quiet the compiler
    instance = instance;

    RD_LOG ( "Checking attributes..." );

    for ( vp = request->config_items; vp != NULL; vp = vp->next )
    {
        RD_LOG ( "Attribute: %s [%d]; Type: %d; Length: %d",
                 get_attr_name ( vp->attribute ), vp->attribute, vp->type, ( int ) vp->length );

        if ( vp->attribute == PW_AUTH_TYPE )
            auth_type = TRUE;
    }

    // Don't touch existing Auth-Type.
    if ( auth_type )
    {
        E_LOG ( "Auth-Type already set.  Not setting to '"
                HTTP_AUTH_TYPE "' (returning RLM_MODULE_NOOP)" );

        return RLM_MODULE_NOOP;
    }

    RD_LOG ( "Setting Auth-Type = " HTTP_AUTH_TYPE );

    pairadd ( &request->config_items, pairmake ( "Auth-Type", HTTP_AUTH_TYPE, T_OP_EQ ) );

    RD_LOG ( "Returning RLM_MODULE_UPDATED" );

    return RLM_MODULE_UPDATED;
}

static int http_authenticate ( void * instance, REQUEST * request )
{
    rlm_http_t *data = instance;

    if ( !request->password || ( request->password->attribute != PW_USER_PASSWORD ) )
    {
        E_LOG ( "No password set (RLM_MODULE_INVALID)" );
        return RLM_MODULE_INVALID;
    }

    if ( request->password->length == 0 )
    {
        E_LOG ( "Empty password set (RLM_MODULE_INVALID)" );
        return RLM_MODULE_INVALID;
    }

    if ( !request->username || ( request->username->attribute != PW_USER_NAME ) )
    {
        E_LOG ( "No username set (RLM_MODULE_INVALID)" );
        return RLM_MODULE_INVALID;
    }

    if ( request->username->length == 0 )
    {
        E_LOG ( "Empty username set (RLM_MODULE_INVALID)" );
        return RLM_MODULE_INVALID;
    }

    int sockfd = socket ( AF_INET, SOCK_STREAM, 0 );

    if ( sockfd < 0 )
    {
        E_LOG ( "Error creating a socket: %s; Responding with RLM_MODULE_FAIL", strerror ( errno ) );
        return RLM_MODULE_FAIL;
    }

    if ( data->timeout > 0 )
    {
        struct timeval timeout;

        timeout.tv_sec = data->timeout;
        timeout.tv_usec = 0;

        if ( setsockopt ( sockfd, SOL_SOCKET, SO_RCVTIMEO, ( const void * ) &timeout, sizeof ( timeout ) ) < 0 )
        {
            E_LOG ( "Error setting SO_RCVTIMEO to %d: %s", data->timeout, strerror ( errno ) );
        }

        if ( setsockopt ( sockfd, SOL_SOCKET, SO_SNDTIMEO, ( const void * ) &timeout, sizeof ( timeout ) ) < 0 )
        {
            E_LOG ( "Error setting SO_SNDTIMEO to %d: %s", data->timeout, strerror ( errno ) );
        }
    }

    RD_LOG ( "Trying to connect to %s:%d...", inet_ntoa ( data->host_addr.sin_addr ), data->port );

    if ( connect ( sockfd, ( struct sockaddr* ) &data->host_addr, sizeof ( data->host_addr ) ) < 0 )
    {
        E_LOG ( "Error connecting to %s:%d (%s); Responding with RLM_MODULE_FAIL",
                inet_ntoa ( data->host_addr.sin_addr ),
                data->port, strerror ( errno ) );

        close ( sockfd );
        return RLM_MODULE_FAIL;
    }

    RD_LOG ( "Connected to %s:%d", inet_ntoa ( data->host_addr.sin_addr ), data->port );

    int resp_code = http_do_request ( sockfd, data, request );

    close ( sockfd );
    sockfd = -1;

    if ( resp_code < 100 || resp_code > 599 )
    {
        E_LOG ( "Error executing the HTTP request to %s:%d; Responding with RLM_MODULE_FAIL",
                inet_ntoa ( data->host_addr.sin_addr ), data->port );

        return RLM_MODULE_FAIL;
    }

    RD_LOG ( "UserName: '%s'; Password: '%s'; Response Code: %d",
             request->username->vp_strvalue, request->password->vp_strvalue,
             resp_code );

    if ( resp_code == 401 )
    {
        RD_LOG ( "Not authorized. Returning RLM_MODULE_REJECT" );

        return RLM_MODULE_REJECT;
    }

    if ( resp_code != 200 )
    {
        E_LOG ( "Invalid response code from %s:%d (%d); Responding with RLM_MODULE_FAIL",
                inet_ntoa ( data->host_addr.sin_addr ), data->port, resp_code );

        return RLM_MODULE_FAIL;
    }

    RD_LOG ( "Authorized; Returning RLM_MODULE_OK" );

    return RLM_MODULE_OK;
}

static int http_do_request ( int sockfd, rlm_http_t* data, REQUEST * request )
{
    struct string str;

    memset ( &str, 0, sizeof ( str ) );

    str.data_size = 0;

    append_str ( &str, request->username->vp_strvalue );
    append_str ( &str, ":" );
    append_str ( &str, request->password->vp_strvalue );

    char * enc_str = base64_encode ( &str );

    str.data_size = 0;

    append_str ( &str, data->req_header );
    append_str ( &str, "Authorization: Basic " );
    append_str ( &str, enc_str );
    append_str ( &str, "\r\n\r\n" );

    if ( strlen ( data->payload ) > 0 )
    {
        append_str ( &str, data->payload );
        append_str ( &str, "\r\n" );
    }

    free ( enc_str );
    enc_str = 0;

    int written = 0;

    RD_LOG ( "Writing: '%s'", str.buffer );

    while ( written < str.data_size )
    {
        int ret = write ( sockfd, str.buffer + written, str.data_size - written );

        if ( ret < 0 )
        {
            E_LOG ( "Error writing to %s:%d: %s", inet_ntoa ( data->host_addr.sin_addr ), data->port,
                    strerror ( errno ) );

            free ( str.buffer );

            return -1;
        }

        written += ret;
    }

    free ( str.buffer );
    memset ( &str, 0, sizeof ( str ) );

    const int tmp_size = 1024 + 1;
    char tmp[tmp_size];
    int off = 0;

    while ( off < tmp_size )
    {
        int ret = read ( sockfd, tmp + off, tmp_size - off );

        if ( ret < 0 )
        {
            E_LOG ( "Error reading from %s:%d: %s", inet_ntoa ( data->host_addr.sin_addr ), data->port,
                    strerror ( errno ) );
            return -1;
        }

        off += ret;

        int i;
        int has_EOL = FALSE;

        for ( i = 0; i < off; ++i )
        {
            if ( tmp[i] == '\r' || tmp[i] == '\n' )
            {
                off = i;
                has_EOL = TRUE;
                break;
            }
        }

        if ( has_EOL )
            break;
    }

    tmp[off] = 0;

    RD_LOG ( "Received response: '%s'", tmp );

    // HTTP/1.1 401 Authorization Required
    // HTTP/1.1 200 OK
    // HTTP/1.1 404 Not Found

    if ( strncmp ( tmp, "HTTP/", 5 ) != 0 )
    {
        E_LOG ( "Invalid response from %s:%d: %s", inet_ntoa ( data->host_addr.sin_addr ), data->port, tmp );
        return -1;
    }

    int resp_code = 0;
    int found_space = FALSE;
    int i;

    for ( i = 0; i < off; ++i )
    {
        if ( !found_space )
        {
            // We ignore anything till we find the first space or tab (tab - just in case)

            if ( tmp[i] == ' ' || tmp[i] == '\t' )
                found_space = TRUE;

            continue;
        }

        if ( tmp[i] == ' ' || tmp[i] == '\t' )
        {
            if ( resp_code == 0 )
            {
                // Any following space until the first non-space character should be ignored as well
                continue;
            }

            // However, if we already read anything (resp_code > 0),
            // the next space after that means the end of the response code

            break;
        }

        // At this point we should get only numbers. Spaces are dealt with above

        if ( tmp[i] < '0' || tmp[i] > '9' )
        {
            // If it is NOT a number, something is wrong!
            resp_code = -1;
            break;
        }

        // Otherwise add the next digit to the response code
        resp_code *= 10;
        resp_code += tmp[i] - '0';
    }

    if ( resp_code < 100 || resp_code > 599 )
    {
        E_LOG ( "Invalid response from %s:%d (%s)", inet_ntoa ( data->host_addr.sin_addr ), data->port, tmp );
        return -1;
    }

    return resp_code;
}

/*
 *  The module name should be the only globally exported symbol.
 *  That is, everything else should be 'static'.
 *
 *  If the module needs to temporarily modify it's instantiation
 *  data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *  The server will then take care of ensuring that the module
 *  is single-threaded.
 */
module_t rlm_http =
{
    RLM_MODULE_INIT,
    "http",
    RLM_TYPE_THREAD_SAFE,    // type
    http_instantiate,        // instantiation
    http_detach,             // detach
    {
        http_authenticate,   // authentication
        http_authorize,      // authorization
        NULL,                // pre-accounting
        NULL,                // accounting
        NULL,                // checksimul
        NULL,                // pre-proxy
        NULL,                // post-proxy
        NULL                 // post-auth
    },
};

static void append_int ( struct string * str, int what )
{
    const int tmp_size = 128 + 1;
    char tmp[tmp_size];

    snprintf ( tmp, tmp_size, "%d", what );
    tmp[tmp_size] = 0;

    append_str ( str, tmp );
}

static void append_str ( struct string * str, const char * what )
{
    append_data ( str, what, strlen ( what ) );
}

static void append_data ( struct string * str, const char * what, int what_len )
{
    if ( what_len < 0 )
        what_len = 0;

    if ( !str->buffer )
    {
        str->data_size = what_len;
        str->mem_size = 1024;

        if ( what_len + 1 > str->mem_size )
        {
            str->mem_size = what_len + 1;
        }

        str->buffer = rad_malloc ( str->mem_size );

        if ( what_len > 0 )
        {
            memcpy ( str->buffer, what, what_len );
        }

        str->buffer[what_len] = 0;

        return;
    }

    if ( what_len < 1 )
        return;

    if ( str->data_size + what_len + 1 <= str->mem_size )
    {
        // + 1 for NULL at the end

        memcpy ( str->buffer + str->data_size, what, what_len );
        str->data_size += what_len;
        str->buffer[str->data_size] = 0;
        return;
    }

    char * org_buf = str->buffer;

    str->mem_size = str->mem_size * 3 / 2 + 1;

    if ( str->data_size + what_len + 1 > str->mem_size )
    {
        // + 1 for NULL at the end

        str->mem_size = str->data_size + what_len + 1;
    }

    str->buffer = rad_malloc ( str->mem_size );

    memcpy ( str->buffer, org_buf, str->data_size );

    free ( org_buf );

    memcpy ( str->buffer + str->data_size, what, what_len );

    str->data_size += what_len;
    str->buffer[str->data_size] = 0;
    return;
}

static const char *BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode_triple ( unsigned char triple[3], char result[4] )
{
    int tripleValue, i;

    tripleValue = triple[0];
    tripleValue *= 256;
    tripleValue += triple[1];
    tripleValue *= 256;
    tripleValue += triple[2];

    for ( i = 0; i < 4; i++ )
    {
        result[3 - i] = BASE64_CHARS[tripleValue % 64];
        tripleValue /= 64;
    }
}

static char * base64_encode ( struct string * src )
{
    int sourcelen = src->data_size;

    char * ret = rad_malloc ( ( sourcelen + 2 ) / 3 * 4 + 2 );

    if ( !ret )
        return ret;

    char * source = src->buffer;
    char * target = ret;

    /* encode all full triples */
    while ( sourcelen >= 3 )
    {
        base64_encode_triple ( ( unsigned char* ) source, target );

        sourcelen -= 3;
        source += 3;
        target += 4;
    }

    /* encode the last one or two characters */
    if ( sourcelen > 0 )
    {
        unsigned char temp[3] = {0, 0, 0};

        memcpy ( temp, source, sourcelen );

        base64_encode_triple ( temp, target );

        target[3] = '=';

        if ( sourcelen == 1 )
            target[2] = '=';

        target += 4;
    }

    /* terminate the string */
    target[0] = 0;

    return ret;
}

#define DEF_NAME(def_name) case def_name: return "" #def_name; break

static char * get_attr_name ( int attr )
{
    switch ( attr )
    {
            DEF_NAME ( PW_USER_NAME );
            DEF_NAME ( PW_USER_PASSWORD );

#if PW_USER_PASSWORD != PW_PASSWORD
            // The same as PW_USER_PASSWORD
            DEF_NAME ( PW_PASSWORD );
#endif

            DEF_NAME ( PW_CHAP_PASSWORD );
            DEF_NAME ( PW_NAS_IP_ADDRESS );
            DEF_NAME ( PW_NAS_PORT );
            DEF_NAME ( PW_SERVICE_TYPE );
            DEF_NAME ( PW_FRAMED_PROTOCOL );
            DEF_NAME ( PW_FRAMED_IP_ADDRESS );
            DEF_NAME ( PW_FRAMED_IP_NETMASK );
            DEF_NAME ( PW_FRAMED_ROUTING );
            DEF_NAME ( PW_FILTER_ID );
            DEF_NAME ( PW_FRAMED_MTU );
            DEF_NAME ( PW_FRAMED_COMPRESSION );
            DEF_NAME ( PW_LOGIN_IP_HOST );
            DEF_NAME ( PW_LOGIN_SERVICE );
            DEF_NAME ( PW_LOGIN_TCP_PORT );
            DEF_NAME ( PW_OLD_PASSWORD );
            DEF_NAME ( PW_REPLY_MESSAGE );
            DEF_NAME ( PW_CALLBACK_NUMBER );
            DEF_NAME ( PW_CALLBACK_ID );

            DEF_NAME ( PW_FRAMED_ROUTE );
            DEF_NAME ( PW_FRAMED_IPXNET );
            DEF_NAME ( PW_STATE );
            DEF_NAME ( PW_CLASS );
            DEF_NAME ( PW_VENDOR_SPECIFIC );
            DEF_NAME ( PW_SESSION_TIMEOUT );
            DEF_NAME ( PW_IDLE_TIMEOUT );
            DEF_NAME ( PW_CALLED_STATION_ID );
            DEF_NAME ( PW_CALLING_STATION_ID );
            DEF_NAME ( PW_NAS_IDENTIFIER );
            DEF_NAME ( PW_PROXY_STATE );

            DEF_NAME ( PW_ACCT_STATUS_TYPE );
            DEF_NAME ( PW_ACCT_DELAY_TIME );
            DEF_NAME ( PW_ACCT_INPUT_OCTETS );
            DEF_NAME ( PW_ACCT_OUTPUT_OCTETS );
            DEF_NAME ( PW_ACCT_SESSION_ID );
            DEF_NAME ( PW_ACCT_AUTHENTIC );
            DEF_NAME ( PW_ACCT_SESSION_TIME );
            DEF_NAME ( PW_ACCT_INPUT_PACKETS );
            DEF_NAME ( PW_ACCT_OUTPUT_PACKETS );
            DEF_NAME ( PW_ACCT_TERMINATE_CAUSE );

            DEF_NAME ( PW_EVENT_TIMESTAMP );

            DEF_NAME ( PW_CHAP_CHALLENGE );
            DEF_NAME ( PW_NAS_PORT_TYPE );
            DEF_NAME ( PW_PORT_LIMIT );

            DEF_NAME ( PW_ARAP_PASSWORD );
            DEF_NAME ( PW_ARAP_FEATURES );
            DEF_NAME ( PW_ARAP_ZONE_ACCESS );
            DEF_NAME ( PW_ARAP_SECURITY );
            DEF_NAME ( PW_ARAP_SECURITY_DATA );
            DEF_NAME ( PW_PASSWORD_RETRY );
            DEF_NAME ( PW_PROMPT );
            DEF_NAME ( PW_CONNECT_INFO );
            DEF_NAME ( PW_CONFIGURATION_TOKEN );
            DEF_NAME ( PW_EAP_MESSAGE );
            DEF_NAME ( PW_MESSAGE_AUTHENTICATOR );

            DEF_NAME ( PW_ARAP_CHALLENGE_RESPONSE );
            DEF_NAME ( PW_NAS_PORT_ID_STRING );
            DEF_NAME ( PW_FRAMED_POOL );
            DEF_NAME ( PW_CHARGEABLE_USER_IDENTITY );
            DEF_NAME ( PW_NAS_IPV6_ADDRESS );

            DEF_NAME ( PW_EXTENDED_ATTRIBUTE );

            DEF_NAME ( PW_DIGEST_RESPONSE );
            DEF_NAME ( PW_DIGEST_ATTRIBUTES );

            DEF_NAME ( PW_FALL_THROUGH );
            DEF_NAME ( PW_RELAX_FILTER );
            DEF_NAME ( PW_EXEC_PROGRAM );
            DEF_NAME ( PW_EXEC_PROGRAM_WAIT );

            DEF_NAME ( PW_AUTH_TYPE );
            DEF_NAME ( PW_PREFIX );
            DEF_NAME ( PW_SUFFIX );
            DEF_NAME ( PW_GROUP );
            DEF_NAME ( PW_CRYPT_PASSWORD );
            DEF_NAME ( PW_CONNECT_RATE );
            DEF_NAME ( PW_ADD_PREFIX );
            DEF_NAME ( PW_ADD_SUFFIX );
            DEF_NAME ( PW_EXPIRATION );
            DEF_NAME ( PW_AUTZ_TYPE );
            DEF_NAME ( PW_ACCT_TYPE );
            DEF_NAME ( PW_SESSION_TYPE );
            DEF_NAME ( PW_POST_AUTH_TYPE );
            DEF_NAME ( PW_PRE_PROXY_TYPE );
            DEF_NAME ( PW_POST_PROXY_TYPE );
            DEF_NAME ( PW_PRE_ACCT_TYPE );
            DEF_NAME ( PW_EAP_TYPE );
            DEF_NAME ( PW_EAP_TLS_REQUIRE_CLIENT_CERT );
            DEF_NAME ( PW_CLIENT_SHORTNAME );
            DEF_NAME ( PW_LOAD_BALANCE_KEY );
            DEF_NAME ( PW_RAW_ATTRIBUTE );
            DEF_NAME ( PW_TNC_VLAN_ACCESS );
            DEF_NAME ( PW_TNC_VLAN_ISOLATE );
            DEF_NAME ( PW_USER_CATEGORY );
            DEF_NAME ( PW_GROUP_NAME );
            DEF_NAME ( PW_HUNTGROUP_NAME );
            DEF_NAME ( PW_SIMULTANEOUS_USE );
            DEF_NAME ( PW_STRIP_USER_NAME );
            DEF_NAME ( PW_HINT );
            DEF_NAME ( PAM_AUTH_ATTR );
            DEF_NAME ( PW_LOGIN_TIME );
            DEF_NAME ( PW_STRIPPED_USER_NAME );
            DEF_NAME ( PW_CURRENT_TIME );
            DEF_NAME ( PW_REALM );
            DEF_NAME ( PW_NO_SUCH_ATTRIBUTE );
            DEF_NAME ( PW_PACKET_TYPE );
            DEF_NAME ( PW_PROXY_TO_REALM );
            DEF_NAME ( PW_REPLICATE_TO_REALM );
            DEF_NAME ( PW_ACCT_SESSION_START_TIME );
            DEF_NAME ( PW_ACCT_UNIQUE_SESSION_ID );
            DEF_NAME ( PW_CLIENT_IP_ADDRESS );
            DEF_NAME ( PW_LDAP_USERDN );
            DEF_NAME ( PW_NS_MTA_MD5_PASSWORD );
            DEF_NAME ( PW_SQL_USER_NAME );
            DEF_NAME ( PW_LM_PASSWORD );
            DEF_NAME ( PW_NT_PASSWORD );
            DEF_NAME ( PW_SMB_ACCOUNT_CTRL );
            DEF_NAME ( PW_SMB_ACCOUNT_CTRL_TEXT );
            DEF_NAME ( PW_USER_PROFILE );
            DEF_NAME ( PW_DIGEST_REALM );
            DEF_NAME ( PW_DIGEST_NONCE );
            DEF_NAME ( PW_DIGEST_METHOD );
            DEF_NAME ( PW_DIGEST_URI );
            DEF_NAME ( PW_DIGEST_QOP );
            DEF_NAME ( PW_DIGEST_ALGORITHM );
            DEF_NAME ( PW_DIGEST_BODY_DIGEST );
            DEF_NAME ( PW_DIGEST_CNONCE );
            DEF_NAME ( PW_DIGEST_NONCE_COUNT );
            DEF_NAME ( PW_DIGEST_USER_NAME );
            DEF_NAME ( PW_POOL_NAME );
            DEF_NAME ( PW_LDAP_GROUP );
            DEF_NAME ( PW_MODULE_SUCCESS_MESSAGE );
            DEF_NAME ( PW_MODULE_FAILURE_MESSAGE );
            DEF_NAME ( PW_REWRITE_RULE );
            DEF_NAME ( PW_SQL_GROUP );
            DEF_NAME ( PW_RESPONSE_PACKET_TYPE );
            DEF_NAME ( PW_DIGEST_HA1 );
            DEF_NAME ( PW_MS_CHAP_USE_NTLM_AUTH );
            DEF_NAME ( PW_MS_CHAP_USER_NAME );
            DEF_NAME ( PW_PACKET_SRC_IP_ADDRESS );
            DEF_NAME ( PW_PACKET_DST_IP_ADDRESS );
            DEF_NAME ( PW_PACKET_SRC_PORT );
            DEF_NAME ( PW_PACKET_DST_PORT );
            DEF_NAME ( PW_PACKET_AUTHENTICATION_VECTOR );
            DEF_NAME ( PW_TIME_OF_DAY );
            DEF_NAME ( PW_REQUEST_PROCESSING_STAGE );
            DEF_NAME ( PW_CACHE_NO_CACHING );
            DEF_NAME ( PW_CACHE_DELETE_CACHE );

            DEF_NAME ( PW_SHA_PASSWORD );
            DEF_NAME ( PW_SSHA_PASSWORD );
            DEF_NAME ( PW_MD5_PASSWORD );
            DEF_NAME ( PW_SMD5_PASSWORD );

            DEF_NAME ( PW_PACKET_SRC_IPV6_ADDRESS );
            DEF_NAME ( PW_PACKET_DST_IPV6_ADDRESS );
            DEF_NAME ( PW_VIRTUAL_SERVER );
            DEF_NAME ( PW_CLEARTEXT_PASSWORD );
            DEF_NAME ( PW_PASSWORD_WITH_HEADER );
            DEF_NAME ( PW_SEND_COA_REQUEST );
            DEF_NAME ( PW_MODULE_RETURN_CODE );
            DEF_NAME ( PW_PACKET_ORIGINAL_TIMESTAMP );
            DEF_NAME ( PW_HOME_SERVER_POOL );
            DEF_NAME ( PW_RECV_COA_TYPE );
            DEF_NAME ( PW_SEND_COA_TYPE );
            DEF_NAME ( PW_MSCHAP_PASSWORD );
            DEF_NAME ( PW_PACKET_TRANSMIT_COUNTER );
            DEF_NAME ( PW_CACHED_SESSION_POLICY );

            DEF_NAME ( PW_CACHE_TTL );
            DEF_NAME ( PW_CACHE_STATUS_ONLY );
            DEF_NAME ( PW_CACHE_ENTRY_HITS );
    }

    return "Unknown";
}
