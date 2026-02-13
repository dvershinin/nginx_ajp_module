#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_ajp.h"
#include "ngx_http_ajp_handler.h"
#include "ngx_http_ajp_module.h"


#define UNKNOWN_METHOD (-1)

extern volatile ngx_cycle_t  *ngx_cycle;

typedef struct {
    ngx_str_t  name;
    ngx_uint_t hash;
    ngx_uint_t code;
} request_known_headers_t;

typedef struct {
    ngx_str_t  name;
    ngx_str_t  lowcase_name;
    ngx_uint_t hash;
} response_known_headers_t;


static void request_known_headers_calc_hash(void);
static void response_known_headers_calc_hash(void);


static request_known_headers_t request_known_headers[] = {
    {ngx_string("accept"),          0, SC_REQ_ACCEPT},
    {ngx_string("accept-charset"),  0, SC_REQ_ACCEPT_CHARSET},
    {ngx_string("accept-encoding"), 0, SC_REQ_ACCEPT_ENCODING},
    {ngx_string("accept-language"), 0, SC_REQ_ACCEPT_LANGUAGE},
    {ngx_string("authorization"),   0, SC_REQ_AUTHORIZATION},
    {ngx_string("connection"),      0, SC_REQ_CONNECTION},
    {ngx_string("content-type"),    0, SC_REQ_CONTENT_TYPE},
    {ngx_string("content-length"),  0, SC_REQ_CONTENT_LENGTH},
    {ngx_string("cookie"),          0, SC_REQ_COOKIE},
    {ngx_string("cookie2"),         0, SC_REQ_COOKIE2},
    {ngx_string("host"),            0, SC_REQ_HOST},
    {ngx_string("pragma"),          0, SC_REQ_PRAGMA},
    {ngx_string("referer"),         0, SC_REQ_REFERER},
    {ngx_string("user-agent"),      0, SC_REQ_USER_AGENT},
    {ngx_null_string, 0, 0}
};

static response_known_headers_t response_known_headers[] = {
    {ngx_string("Content-Type"),     ngx_string("content-type"), 0},
    {ngx_string("Content-Language"), ngx_string("content-language"), 0},
    {ngx_string("Content-Length"),   ngx_string("content-length"), 0},
    {ngx_string("Date"),             ngx_string("date"), 0},
    {ngx_string("Last-Modified"),    ngx_string("last-modified"), 0},
    {ngx_string("Location"),         ngx_string("location"), 0},
    {ngx_string("Set-Cookie"),       ngx_string("set-cookie"), 0},
    {ngx_string("Set-Cookie2"),      ngx_string("set-cookie2"), 0},
    {ngx_string("Servlet-Engine"),   ngx_string("servlet-engine"), 0},
    {ngx_string("Status"),           ngx_string("status"), 0},
    {ngx_string("WWW-Authenticate"), ngx_string("www-authenticate"), 0},
    {ngx_null_string, ngx_null_string, 0}
};


#define SESSION_ROUTE_HEADER_LOWCASE "session-route"

static ngx_uint_t session_route_header_hash;


/* This will be called in the ajp_module's init_process function. */
void
ajp_header_init(void)
{
    request_known_headers_calc_hash();
    response_known_headers_calc_hash();

    session_route_header_hash = ngx_hash_key((u_char *)SESSION_ROUTE_HEADER_LOWCASE,
                                                sizeof(SESSION_ROUTE_HEADER_LOWCASE) - 1);
}


static void
request_known_headers_calc_hash (void)
{
    static ngx_int_t         is_calc_request_hash = 0;
    request_known_headers_t *header;

    if (is_calc_request_hash) {
        return;
    }

    is_calc_request_hash = 1;

    header = request_known_headers;

    while (header->name.len != 0) {
        header->hash = ngx_hash_key(header->name.data, header->name.len);

        header++;
    }
}


static void
response_known_headers_calc_hash(void)
{
    static ngx_int_t          is_calc_response_hash = 0;
    response_known_headers_t *header;

    if (is_calc_response_hash) {
        return;
    }

    is_calc_response_hash = 1;

    header = response_known_headers;

    while (header->name.len != 0) {
        header->hash =
            ngx_hash_key(header->lowcase_name.data, header->lowcase_name.len);

        header++;
    }
}


static ngx_uint_t
sc_for_req_get_headers_num(ngx_ajp_proxy_headers_t *headers, ngx_list_part_t *part)
{
    ngx_table_elt_t *header;
    ngx_uint_t       i, num = 0;

    if (part) {
        header = part->elts;
        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                header = part->elts;
                i = 0;
            }
            if (!ngx_hash_find(&headers->hash, header[i].hash,
                               header[i].lowcase_key, header[i].key.len)) {
                num++;
            }
        }
    }

    return num;
}


static ngx_int_t
sc_for_req_get_uri(ngx_http_request_t *r, ngx_str_t *uri)
{
    uintptr_t escape;

    escape = 0;

    if (r->quoted_uri || r->internal) {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data,
                r->uri.len, NGX_ESCAPE_URI);
    }

    if (escape) {
        uri->len = r->uri.len + escape;
        uri->data = ngx_palloc(r->pool, uri->len);

        if (uri->data == NULL) {
            return -1;
        }

        ngx_escape_uri(uri->data, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    }
    else {
        uri->len = r->uri.len;
        uri->data = r->uri.data;
    }

    return 0;
}


static ngx_int_t
request_known_headers_find_hash (ngx_uint_t hash)
{
    request_known_headers_t *header;

    header = request_known_headers;

    while (header->name.len != 0) {
        if (header->hash == hash) {
            return header->code;
        }

        header++;
    }

    return UNKNOWN_METHOD;
}


static int
sc_for_req_header(ngx_table_elt_t *header)
{
    size_t len = header->key.len;

    /* ACCEPT-LANGUAGE is the longest header */
    if (len < 4 || len > 15) {
        return UNKNOWN_METHOD;
    }

    return (int)request_known_headers_find_hash(header->hash);
}


static ngx_str_t *
sc_for_req_get_header_value_by_hash(ngx_list_part_t *part, ngx_uint_t hash)
{
    ngx_uint_t       i;
    ngx_table_elt_t *header;

    header = part->elts;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == hash) {
            return &header[i].value;
        }
    }

    return NULL;
}


static int
sc_for_req_method_by_id(ngx_http_request_t *r)
{
    int method_id = r->method;

    if (method_id <= NGX_HTTP_UNKNOWN || method_id > NGX_HTTP_TRACE) {
        return UNKNOWN_METHOD;
    }

    switch (method_id) {
        case NGX_HTTP_GET:
            return SC_M_GET;
        case NGX_HTTP_HEAD:
            return SC_M_HEAD;
        case NGX_HTTP_POST:
            return SC_M_POST;
        case NGX_HTTP_PUT:
            return SC_M_PUT;
        case NGX_HTTP_DELETE:
            return SC_M_DELETE;
        case NGX_HTTP_MKCOL:
            return SC_M_MKCOL;
        case NGX_HTTP_COPY:
            return SC_M_COPY;
        case NGX_HTTP_MOVE:
            return SC_M_MOVE;
        case NGX_HTTP_OPTIONS:
            return SC_M_OPTIONS;
        case NGX_HTTP_PROPFIND:
            return SC_M_PROPFIND;
        case NGX_HTTP_PROPPATCH:
            return SC_M_PROPPATCH;
        case NGX_HTTP_LOCK:
            return SC_M_LOCK;
        case NGX_HTTP_UNLOCK:
            return SC_M_UNLOCK;
        case NGX_HTTP_TRACE:
            return SC_M_TRACE;
        default:
            return UNKNOWN_METHOD;
    }
}


static void
sc_for_auth_type(ngx_str_t *auth, ngx_str_t *auth_type)
{
    size_t     i;

    auth_type->len = 0;

    if (auth == NULL) {
        return;
    }

    for(i = 0; i < auth->len; i++) {
        if (auth->data[i] == ' ') {
            break;
        }
    }

    if (i > 0) {
        auth_type->data = auth->data;
        auth_type->len = i;
    }
}


static void
sc_for_req_auth_type(ngx_http_request_t *r, ngx_str_t *auth_type)
{
    ngx_str_t *auth = r->headers_in.authorization == NULL ? NULL
                   : &r->headers_in.authorization->value;

    sc_for_auth_type(auth, auth_type);
}


static ngx_int_t
get_res_header_for_sc(int sc, ngx_table_elt_t *h)
{
    response_known_headers_t *header;

    sc = sc & 0X00FF;

    if(sc <= SC_RES_HEADERS_NUM && sc > 0) {
        header = &response_known_headers[sc - 1];
        h->key = header->name;
        h->lowcase_key = header->lowcase_name.data;
        h->hash = header->hash;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
get_res_unknown_header_by_str(ngx_str_t *name,
    ngx_table_elt_t *h, ngx_pool_t *pool)
{
    h->key = *name;

    h->lowcase_key = ngx_pnalloc(pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    h->hash = ngx_hash_strlow(h->lowcase_key, h->key.data, h->key.len);
    return NGX_OK;
}

#if (NGX_HTTP_SSL)

static ngx_uint_t
sc_for_req_get_ssl_cert(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *data) {
    ngx_ssl_get_raw_certificate(c, pool, data);
    return data->len;
}

static ngx_uint_t
sc_for_req_get_ssl_cipher(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *data) {
    ngx_ssl_get_cipher_name(c, pool, data);
    data->len = ngx_strlen(data->data);
    return data->len;
}

static ngx_uint_t
sc_for_req_get_ssl_session(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *data) {
    ngx_ssl_get_session_id(c, pool, data);
    return data->len;
}

static ngx_uint_t
sc_for_req_get_ssl_key_size(ngx_connection_t *c, ngx_pool_t *pool) {
    int usekeysize = 0, algkeysize = 0;
    const SSL_CIPHER *cipher;

    if(c->ssl->connection != NULL)
        if((cipher = SSL_get_current_cipher(c->ssl->connection)) != NULL)
            usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);

    return usekeysize;
}

#endif

/*
 Message structure

 AJPV13_REQUEST/AJPV14_REQUEST=
 request_prefix (1) (byte)
 method         (byte)
 protocol       (string)
 req_uri        (string)
 remote_addr    (string)
 remote_host    (string)
 server_name    (string)
 server_port    (short)
 is_ssl         (boolean)
 num_headers    (short)
 num_headers*(req_header_name header_value)

 ?context       (byte)(string)
 ?servlet_path  (byte)(string)
 ?remote_user   (byte)(string)
 ?auth_type     (byte)(string)
 ?query_string  (byte)(string)
 ?jvm_route     (byte)(string)
 ?ssl_cert      (byte)(string)
 ?ssl_cipher    (byte)(string)
 ?ssl_session   (byte)(string)
 ?ssl_key_size  (byte)(int)
 request_terminator (byte)
 ?body          content_length*(var binary)
 */

ngx_int_t
ajp_marshal_into_msgb(ajp_msg_t *msg,
    ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf)
{
    int                  sc;
    int                  method;
    u_char               is_ssl = 0;
    uint16_t             port;
    ngx_str_t            uri, *remote_host, *remote_addr;
    ngx_str_t            temp_str, *jvm_route, port_str, param_str, val_str;
    ngx_log_t           *log;
    ngx_uint_t           i, num_headers = 0;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;
    struct sockaddr_in  *addr;
    //ngx_http_variable_value_t val;
    ngx_http_script_engine_t     e, le;
    ngx_http_script_code_pt      code;
    ngx_http_script_len_code_pt  lcode;
    ngx_ajp_proxy_headers_t     *headers;
    ngx_table_elt_t              header_tmp;
    ngx_str_t                    authorization_str = ngx_null_string,
                                 jvm_route_str = ngx_null_string;
    u_char                      *tmp, *key_tmp, *val_tmp, *lowcase_key_tmp,
                                *authorization_val_tmp, *jvm_route_val_tmp;
    size_t                       key_len, val_len,
                                 max_key_len = 0, max_val_len = 0;

    log = r->connection->log;

    if ((method = sc_for_req_method_by_id(r)) == UNKNOWN_METHOD) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ajp_marshal_into_msgb - No such method %ui", r->method);
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL)
    is_ssl = (u_char) r->http_connection->ssl;
#endif

#if (NGX_HTTP_CACHE)
    headers = r->upstream->cacheable ? &alcf->headers_cache : &alcf->headers;
#else
    headers = &alcf->headers;
#endif

    part = &r->headers_in.headers.part;

    num_headers = sc_for_req_get_headers_num(headers,
                                             alcf->upstream.pass_request_headers ? part : NULL);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                      "ajp_marshal_into_msgb: request headers number = %d", num_headers);

    // Calculate maximal key and value length for temporary buffer allocation
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        max_key_len = ngx_max(max_key_len, key_len);
        max_val_len = ngx_max(max_val_len, val_len);

        if (val_len > 0) {
            num_headers++;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                      "ajp_marshal_into_msgb: total headers number = %d", num_headers);

    // Allocate keys and values temporary storage
    tmp = ngx_palloc(r->pool, max_key_len * 2 + max_val_len * 3);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    key_tmp = tmp;
    lowcase_key_tmp = key_tmp + max_key_len;
    val_tmp = lowcase_key_tmp + max_key_len;
    authorization_val_tmp = val_tmp + max_val_len;
    jvm_route_val_tmp = authorization_val_tmp + max_val_len;

    remote_host = remote_addr = &r->connection->addr_text;

    addr = (struct sockaddr_in *) r->connection->local_sockaddr;
    /*'struct sockaddr_in' and 'struct sockaddr_in6' has the same offset of port*/
    port = ntohs(addr->sin_port);

    if (sc_for_req_get_uri(r, &uri) != 0) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "Into ajp_marshal_into_msgb, uri: \"%V\", version: \"%V\"",
                   &uri, &r->http_protocol);

    ajp_msg_reset(msg);

    if (ajp_msg_append_uint8(msg, CMD_AJP13_FORWARD_REQUEST)  ||
            ajp_msg_append_uint8(msg, (u_char) method)        ||
            ajp_msg_append_string(msg, &r->http_protocol)     ||
            ajp_msg_append_string(msg, &uri)                  ||
            ajp_msg_append_string(msg, remote_addr)           ||
            ajp_msg_append_string(msg, remote_host)           ||
            ajp_msg_append_string(msg, &r->headers_in.server) ||
            ajp_msg_append_uint16(msg, port)                  ||
            ajp_msg_append_uint8(msg, is_ssl)                 ||
            ajp_msg_append_uint16(msg, (uint16_t) num_headers)) {

        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ajp_marshal_into_msgb: "
                      "Error appending the message begining");
        return AJP_EOVERFLOW;
    }

    // Marshal default and configured headers
    header_tmp.key.data = key_tmp;
    header_tmp.value.data = val_tmp;
    header_tmp.lowcase_key = lowcase_key_tmp;
    header_tmp.next = NULL;

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }
	// TODO Suppress Authorization type and JVM route request attributes (see below)
	//  if respective headers were configured with or computed to the empty value?

        e.pos = key_tmp;

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        e.pos = val_tmp;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        header_tmp.key.len = key_len;
        header_tmp.value.len = val_len;
        header_tmp.hash = ngx_hash_strlow(header_tmp.lowcase_key, header_tmp.key.data, key_len);

        if ((sc = sc_for_req_header(&header_tmp)) != UNKNOWN_METHOD) {
            if (ajp_msg_append_uint16(msg, (uint16_t)sc)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }
        else {
            if (ajp_msg_append_string(msg, &header_tmp.key)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }

        /*
        // Keep configured Connection header as is
        if (sc == SC_REQ_CONNECTION) {
            if (alcf->keep_conn) {
                header_tmp.value.data = (u_char *)"keep-alive";
                header_tmp.value.len = sizeof("keep-alive") - 1;
            }
            else {
                header_tmp.value.data = (u_char *)"close";
                header_tmp.value.len = sizeof("close") - 1;
            }
        }
        */

        if (ajp_msg_append_string(msg, &header_tmp.value)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the header value");
            return AJP_EOVERFLOW;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                       "ajp_marshal_into_msgb: Header[%d] [%V] = [%V], size:%z",
                       i, &header_tmp.key, &header_tmp.value, ngx_buf_size(msg->buf));

        // Store selected headers value for later lookup
        if (sc == SC_REQ_AUTHORIZATION) {
            ngx_memcpy(authorization_val_tmp, header_tmp.value.data, header_tmp.value.len);
            authorization_str.data = authorization_val_tmp;
            authorization_str.len = header_tmp.value.len;
        }

        if (header_tmp.hash == session_route_header_hash) {
            ngx_memcpy(jvm_route_val_tmp, header_tmp.value.data, header_tmp.value.len);
            jvm_route_str.data = jvm_route_val_tmp;
            jvm_route_str.len = header_tmp.value.len;
        }
    }

    // Marshal request headers
    if (alcf->upstream.pass_request_headers) {
        header = part->elts;

        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len)) {
                continue;
            }

            if ((sc = sc_for_req_header(&header[i])) != UNKNOWN_METHOD) {
                if (ajp_msg_append_uint16(msg, (uint16_t)sc)) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "ajp_marshal_into_msgb: "
                                  "Error appending the header name");
                    return AJP_EOVERFLOW;
                }
            }
            else {
                if (ajp_msg_append_string(msg, &header[i].key)) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "ajp_marshal_into_msgb: "
                                  "Error appending the header name");
                    return AJP_EOVERFLOW;
                }
            }

            if (sc == SC_REQ_CONNECTION) {
                if (alcf->keep_conn) {
                    header[i].value.data = (u_char *)"keep-alive";
                    header[i].value.len = sizeof("keep-alive") - 1;
                }
                else {
                    header[i].value.data = (u_char *)"close";
                    header[i].value.len = sizeof("close") - 1;
                }
            }

            if (ajp_msg_append_string(msg, &header[i].value)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the header value");
                return AJP_EOVERFLOW;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "ajp_marshal_into_msgb: Header[%d] [%V] = [%V], size:%z",
                           i, &header[i].key, &header[i].value, ngx_buf_size(msg->buf));
        }
    }

    if (r->headers_in.user.len != 0) {
        if (ajp_msg_append_uint8(msg, SC_A_REMOTE_USER) ||
                ajp_msg_append_string(msg, &r->headers_in.user)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the remote user");
            return AJP_EOVERFLOW;
        }
    }

    // Consider "Authorization" from configured headers first
    if (authorization_str.len > 0) {
        sc_for_auth_type(&authorization_str, &temp_str);
    }
    else {
        sc_for_req_auth_type(r, &temp_str);
    }
    if (temp_str.len > 0) {
        if (ajp_msg_append_uint8(msg, SC_A_AUTH_TYPE) ||
                ajp_msg_append_string(msg, &temp_str))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the auth type");
            return AJP_EOVERFLOW;
        }
    }

    if (r->args.len > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "ajp_marshal_into_msgb: append_args=\"%V\"", &r->args);

        if (ajp_msg_append_uint8(msg, SC_A_QUERY_STRING) ||
                ajp_msg_append_string(msg, &r->args)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the query string");
            return AJP_EOVERFLOW;
        }
    }

    // Consider "Session-Route" from configured headers first
    if (jvm_route_str.len > 0) {
        jvm_route = &jvm_route_str;
    }
    else {
        jvm_route = sc_for_req_get_header_value_by_hash(&r->headers_in.headers.part, session_route_header_hash);
    }
    if (jvm_route != NULL) {
        if (ajp_msg_append_uint8(msg, SC_A_JVM_ROUTE) ||
                ajp_msg_append_string(msg, jvm_route)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the jvm route");
            return AJP_EOVERFLOW;
        }
    }

    // secret
    ngx_str_t secret = alcf->secret;
    if (secret.data != NULL) {
        if (ajp_msg_append_uint8(msg, SC_A_SECRET) ||
                ajp_msg_append_string(msg, &secret)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending the secret");
            return AJP_EOVERFLOW;
        }
    }

#if (NGX_HTTP_SSL)

    /*
     * Only lookup SSL variables if we are currently running HTTPS.
     * Furthermore ensure that only variables get set in the AJP message
     * that are not NULL and not empty.
     */
    if(is_ssl) {
        ngx_connection_t *c = r->connection;
        ngx_pool_t *pool = r->pool;
        ngx_uint_t keysize;
        ngx_str_t cert_str, cipher_str, session_str;

        if(sc_for_req_get_ssl_cert(c, pool, &cert_str) > 0) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CERT) ||
                    ajp_msg_append_string(msg, &cert_str)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the SSL certificates");
                return AJP_EOVERFLOW;
            }
        }

        if(sc_for_req_get_ssl_cipher(c, pool, &cipher_str) > 0) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CIPHER) ||
                    ajp_msg_append_string(msg, &cipher_str)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the SSL ciphers");
                return AJP_EOVERFLOW;
            }
        }

        if(sc_for_req_get_ssl_session(c, pool, &session_str) > 0) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_SESSION) ||
                    ajp_msg_append_string(msg, &session_str)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the SSL session");
                return AJP_EOVERFLOW;
            }
        }

        /* ssl_key_size is required by Servlet 2.3 API */
        if((keysize = sc_for_req_get_ssl_key_size(c, pool)) > 0) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_KEY_SIZE) ||
                    ajp_msg_append_uint16(msg, (uint16_t) keysize)) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_marshal_into_msgb: "
                              "Error appending the SSL key size");
                return AJP_EOVERFLOW;
            }
        }
    }
#endif

    /* Forward the remote port information, which was forgotten
     * from the builtin data of the AJP 13 protocol.
     * Since the servlet spec allows to retrieve it via getRemotePort(),
     * we provide the port to the Tomcat connector as a request
     * attribute. Modern Tomcat versions know how to retrieve
     * the remote port from this attribute.
     */
    {
        u_char buf[6] = {0};
        temp_str.data = (u_char *)SC_A_REQ_REMOTE_PORT;
        temp_str.len = sizeof(SC_A_REQ_REMOTE_PORT) - 1;

        addr = (struct sockaddr_in *) r->connection->sockaddr;

        /*
         * 'struct sockaddr_in' and 'struct sockaddr_in6' has the same
         * offset of port */
        port = ntohs(addr->sin_port);

        /* port < 65536 */
        ngx_snprintf(buf, 6, "%d", port);
        port_str.data = buf;
        port_str.len = ngx_strlen(buf);

        if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
            ajp_msg_append_string(msg, &temp_str)         ||
            ajp_msg_append_string(msg, &port_str)) {

            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_marshal_into_msgb: "
                          "Error appending attribute %V=%V",
                          &temp_str, &port_str);
            return AJP_EOVERFLOW;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                "ajp_marshal_into_msgb: attribute %V %V", &temp_str, &port_str);

        if (alcf->script_url.len > 0) {
	        param_str.data = (u_char *)"SCRIPT_URL";
	        param_str.len = ngx_strlen("SCRIPT_URL");
 	        val_str.data = (u_char *)alcf->script_url.data;
	        val_str.len = alcf->script_url.len;

                ngx_http_script_run(r, &val_str, alcf->param_lengths->elts, 0, alcf->param_values->elts);

	        if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
                        ajp_msg_append_string(msg, &param_str)   ||
                        ajp_msg_append_string(msg, &val_str)) {
                        ngx_log_error(NGX_LOG_ERR, log, 0,
                            "ajp_marshal_into_msgb: "
                            "Error appending attribute %V=%V",
                        &param_str, &val_str);
                    return AJP_EOVERFLOW;
            }
        }
    }

    if (ajp_msg_append_uint8(msg, SC_A_ARE_DONE)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "ajp_marshal_into_msgb: "
                      "Error appending the message end");
        return AJP_EOVERFLOW;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ajp_marshal_into_msgb: Done, buff_size: %z",
                   ngx_buf_size(msg->buf));

    return NGX_OK;
}


/*
    AJPV13_RESPONSE/AJPV14_RESPONSE:=
    response_prefix (2)
    status          (short)
    status_msg      (short)
    num_headers     (short)
    num_headers*(res_header_name header_value)
    *body_chunk
    terminator      boolean <! -- recycle connection or not  -->

    req_header_name :=
    sc_req_header_name | (string)

    res_header_name :=
    sc_res_header_name | (string)

    header_value :=
    (string)

    body_chunk :=
    length  (short)
    body    length*(var binary)
*/

ngx_int_t
ajp_unmarshal_response(ajp_msg_t *msg,
    ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf)
{
    int                             i;
    u_char                          line[1024], *last;
    uint16_t                        status;
    uint16_t                        name;
    uint16_t                        num_headers;
    ngx_int_t                       rc;
    ngx_str_t                       str;
    ngx_log_t                      *log;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    log = r->connection->log;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "ajp_unmarshal_response");

    rc = ajp_msg_get_uint16(msg, &status);
    if (rc != NGX_OK) {
        return rc;
    }

    u->headers_in.status_n = status;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ajp_unmarshal_response: status = %d", status);

    rc = ajp_msg_get_string(msg, &str);
    if (rc == NGX_OK) {
        if (str.len > 0) {
            last = ngx_snprintf(line, 1024, "%d %V", status, &str);

            str.data = line;
            str.len = last - line;

            u->headers_in.status_line.data = ngx_pstrdup(r->pool, &str);
            u->headers_in.status_line.len = str.len;

        } else {
            u->headers_in.status_line.data = NULL;
            u->headers_in.status_line.len = 0;
        }

    } else {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ajp_unmarshal_response: status_line = \"%V\"",
                   &u->headers_in.status_line);

    if (u->state) {
        u->state->status = u->headers_in.status_n;
    }

    num_headers = 0;
    rc = ajp_msg_get_uint16(msg, &num_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "ajp_unmarshal_response: Number of headers is = %d",
                   num_headers);

    for(i = 0 ; i < (int) num_headers ; i++) {

        rc  = ajp_msg_peek_uint16(msg, &name);
        if (rc != NGX_OK) {
            return rc;
        }

        /* a header line has been parsed successfully */

        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        if ((name & 0XFF00) == 0XA000) {
            ajp_msg_get_uint16(msg, &name);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http ajp known header: %08Xd", name);

            rc = get_res_header_for_sc(name, h);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_unmarshal_response: No such sc (%08Xd)",
                              name);
                return NGX_ERROR;
            }

        } else {
            name = 0;
            rc = ajp_msg_get_string(msg, &str);
            if (rc != NGX_OK) {
                if (rc != AJP_EOVERFLOW) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "ajp_unmarshal_response: Null header name");
                }
                return rc;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                    "http ajp unknown header: %V", &str);

            rc = get_res_unknown_header_by_str(&str, h, r->pool);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        rc = ajp_msg_get_string(msg, &h->value);
        if (rc != NGX_OK) {
            if (rc != AJP_EOVERFLOW) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "ajp_unmarshal_response: Null header value");
            }
            return rc;
        }

        hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "ajp_unmarshal_response: hh->handler error: \"%V: %V\"",
                          &h->key, &h->value);

            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http ajp header: \"%V: %V\"", &h->key, &h->value);
    }

    return NGX_OK;
}
