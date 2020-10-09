

/*******************************************************************************
 * epmap.c - Enumerate local dynamic endpoints on a remote endpoint mapper. 
 * An endpoint mapper is a service on a remote procedure call (RPC) server that
 * maintains a database of dynamic endpoints and allows clients to map an  
 * interface/object UUID pair to a local dynamic endpoint. This trivial tool
 * can be used to identify services that have registered with DCE/RPC endpoint
 * mapper. Usage: epmap [-p port] hostname.
 *
 * Endpoint Mapper interface: e1af8308-5d1f-11c9-91a4-08002b14a0fa 
 * 
 * WIP, I have to fix several things.
 *
 * Output example: 
 * epdump -p 135 192.168.1.4
 *
 * Binding to portmapper: 192.168.1.4[135] ...
 * Querying Endpoint Mapper Database...
 *
 * UUID: d95afe70-a6d5-4259-822e-2c84da1ddb0d
 * ncacn_ip_tcp:192.168.1.4[49152]
 *
 * UUID: 367abb81-9844-35f1-ad32-98f038001003
 * ncacn_ip_tcp:192.168.1.4[49162]
 *
 * UUID: b58aa02e-2884-4e97-8176-4ee06d794184
 * ncacn_np:192.168.1.4[\\pipe\trkwks]
 *
 * UUID: b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 KeyIso
 * ncacn_np:192.168.1.4[\\pipe\lsass]
 *
 * UUID: b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 KeyIso
 * ncacn_np:192.168.1.4[\\PIPE\protected_storage]
 *
 * UUID: 12345778-1234-abcd-ef00-0123456789ac
 * ncacn_np:192.168.1.4[\\pipe\lsass]
 *
 * UUID: 12345778-1234-abcd-ef00-0123456789ac
 * ncacn_np:192.168.1.4[\\PIPE\protected_storage]
 * 
 * UUID: 12345778-1234-abcd-ef00-0123456789ac
 * ncacn_ip_tcp:192.168.1.4[49155]
 *
 *
 * 
 *    
 *
 ******************************************************************************/


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char byte;

typedef struct uuid {
   uint32_t  time_low;
   uint16_t  time_mid;
   uint16_t  time_hi_and_version;
   uint8_t   clock_seq_hi_and_reserved;
   uint8_t   clock_seq_low;
   byte      node[6];
} uuid_t, *uuid_p_t;

#define UUID_SIZE  16

typedef uint16_t p_context_id_t;

typedef struct p_syntax_id {
   uuid_t   if_uuid;    
   uint32_t if_version; /* Major/Minor version. */
} p_syntax_id_t;

/* Elements in a presentation context list. */
typedef struct _p_cont_elem {
   p_context_id_t p_cont_id;
   uint8_t       n_transfer_syn;
   uint8_t       reserved;
   p_syntax_id_t abstract_syntax;  
   p_syntax_id_t *transfer_syntaxes; 
} p_cont_elem_t;

/* Presentation context list. */
typedef struct p_cont_list {
   uint8_t        n_context_elem;
   uint8_t        reserved;
   uint16_t       reserved2;
   p_cont_elem_t *p_cont_elem;
} p_cont_list_t;

/* Common Authentication Verifier. */
typedef struct auth_verifier_co {
   /* Restore 4-byte alignment */
   /* uint8_t auth_pad[]; */
   uint8_t auth_type;
   uint8_t auth_level;
   uint8_t auth_pad_length;
   uint8_t auth_reserved;
   uint8_t auth_context_id;
   uint8_t *auth_value; /* Size is auth_length. */
} auth_verifier_co_t;

/* BIND PDU header */
typedef struct rpcconn_bind_hdr {
   uint8_t  rpc_vers;       /* RPC version. */   
   uint8_t  rpc_vers_minor; /* Minor version. */   
   uint8_t  ptype;          /* Bind PDU. */
   uint8_t  pfc_flags;      /* PFC Flags. */
   uint8_t  packed_drep[4]; /* NDR data representation format label. */
   uint16_t frag_length;    /* Total length of fragment. */
   uint16_t auth_length;    /* Length of auth_value. */
   uint32_t call_id;        /* Call identifier. */
   uint16_t max_xmit_frag;  /* Max transmit fragment size. */
   uint16_t max_recv_frag;  /* Max receive fragment size. */ 
   uint32_t assoc_group_id; /* Incarnation of client-server assoc group. */
   p_cont_list_t p_context_elem; /* Presentation context list. */
   auth_verifier_co_t auth_verifier; /* if auth_length != 0. */     
} rpcconn_bind_hdr_t;

typedef struct port_any {
   uint16_t length;
   char     *port_spec;  
} port_any_t;

/* Result of a presentation context negotiation. */
typedef uint16_t p_cont_def_result_t;
/* Reason for rejection of a context element. */
typedef uint16_t p_provider_reason_t;

typedef struct p_result {
   p_cont_def_result_t result;
   p_provider_reason_t reason;
   p_syntax_id_t       transfer_syntax;
} p_result_t;

typedef struct p_result_list {
   uint8_t  n_results;
   uint8_t  reserved;
   uint16_t reserved2;
   p_result_t *p_results; 
} p_result_list_t;

/* BIND_ACK PDU header */ 
typedef struct rpcconn_bind_ack_hdr {
   uint8_t  rpc_vers;       
   uint8_t  rpc_vers_minor; 
   uint8_t  ptype;          
   uint8_t  pfc_flags;      
   byte     packed_drep[4]; 
   uint16_t frag_length;    
   uint16_t auth_length;    
   uint32_t call_id;        
   uint16_t max_xmit_frag;  
   uint16_t max_recv_frag;  
   uint32_t assoc_group_id; /* Returned assoc_group_id. */    
   port_any_t sec_addr;     /* Optional secondary address. */
   /* Restore 8-octet alignment. */
   /* uint8_t  pad2[]; */            
   p_result_list_t p_result_list;    /* Variable size. */
   auth_verifier_co_t auth_verifier; /* if auth_length != 0. */
} rpcconn_bind_ack_hdr_t;

/* Presentation context reject */
typedef uint16_t p_reject_reason_t;

typedef struct version {
   uint8_t  major;
   uint8_t  minor;
} version_t;

typedef version_t p_rt_version_t;

typedef struct p_rt_versions_supported {
   uint8_t  n_protocols;
   p_rt_version_t *p_protocols;
} p_rt_versions_supported_t;

/* BIND NAK PDU header */
typedef struct rpcconn_bind_nak_hdr {
   uint8_t  rpc_vers;
   uint8_t  rpc_vers_minor;
   uint8_t  ptype;
   uint8_t  pfc_flags;
   byte     packed_drep[4];
   uint16_t frag_length;
   uint16_t auth_length;
   uint32_t call_id;
   p_reject_reason_t provider_reject_reason;
   p_rt_versions_supported_t *versions; /* if reject reason is 4. */                        
} rpcconn_bind_nak_hdr_t; 

/* Reasons for rejection of an association in the bind nak PDU. */
#define REASON_NOT_SPECIFIED           0
#define TEMPORARY_CONGESTION           1
#define LOCAL_LIMIT_EXCEEDED           2
#define CALLED_PADDR_UNKNOWN           3 /* Not used. */
#define PROTOCOL_VERSION_NOT_SUPPORTED 4
#define DEFAULT_CONTEXT_NOT_SUPPORTED  5 /* Not used. */
#define USER_DATA_NOT_READABLE         6 /* Not used. */ 
#define NO_PSAP_AVAILABLE              7 /* Not used. */

/* REQUEST PDU header */
typedef struct rpcconn_request_hdr {
   uint8_t  rpc_vers;        /* RPC version. */
   uint8_t  rpc_vers_minor;  /* Minor version. */
   uint8_t  ptype;           /* Request PDU. */
   uint8_t  pfc_flags;       /* PFC Flags. */
   uint8_t  packed_drep[4];  /* NDR data representation format label. */
   uint16_t frag_length;     /* Total length of fragment. */
   uint16_t auth_length;     /* Length of auth_value. */
   uint32_t call_id;         /* Call identifier. */
   uint32_t alloc_hint;      /* Allocation hint. */
   p_context_id_t p_cont_id; /* Presentation context. */ 
   uint16_t opnum;           /* Operation # within the interface! */
   uuid_t   object; /* Only present if the PFC_OBJECT_UUID field is non zero. */ 
   /* Stub data, 8-octet aligned. */
   auth_verifier_co_t auth_verifier; /* if auth_length != 0 */
} rpcconn_request_hdr_t;

/* RESPONSE PDU header */
typedef struct rpcconn_response {
   uint8_t  rpc_vers;
   uint8_t  rpc_vers_minor;
   uint8_t  ptype;
   uint8_t  pfc_flags;
   uint8_t  packed_drep[4];
   uint16_t frag_length;
   uint16_t auth_length;
   uint32_t call_id;
   uint32_t alloc_hint;
   p_context_id_t p_cont_id;
   uint8_t  cancel_count;
   uint8_t  reserved;
   /* Stub data here, 8-octet aligned. */
   auth_verifier_co_t auth_verifier; /* if auth_length != 0. */
} rpcconn_response_hdr_t;

/* FAULT PDU header */
typedef struct rpcconn_fault_hdr {
   uint8_t  rpc_vers;
   uint8_t  rpc_vers_minor;
   uint8_t  ptype;
   uint8_t  pfc_flags;
   byte     packed_drep[4];
   uint16_t frag_length;
   uint16_t auth_length;
   uint32_t call_id;
   uint32_t alloc_hint;
   p_context_id_t p_cont_id; /* Presentation context. */
   uint8_t  cancel_count;    /* Received cancel count. */
   uint8_t  reserved;  
   uint32_t status;          /* Run-time fault code or zero. */ 
   uint8_t  reserved2[4];
   /* Stub data here, 8-octet aligned. */
   auth_verifier_co_t auth_verifier; /* if auth_length != 0. */
} rpcconn_fault_hdr_t;

/* SHUTDOWN PDU header */
typedef struct rpcconn_shutdown_hdr {
   uint8_t   rpc_vers;
   uint8_t   rpc_vers_minor;
   uint8_t   ptype;
   uint8_t   pfc_flags;
   byte      packed_drep[4];
   uint16_t  frag_length;
   uint16_t  auth_length;
   uint32_t  call_id;
} rpcconn_shutdown_hdr_t;

#define DEFAULT_EPMAP_PORT 135

/* PDU types */
#define RPC_PTYPE_REQUEST        0x00 /* CO/CL */
#define RPC_PTYPE_PING           0x01 /* CL    */
#define RPC_PTYPE_RESPONSE       0x02 /* CO/CL */
#define RPC_PTYPE_FAULT          0x03 /* CO/CL */
#define RPC_PTYPE_WORKING        0x04 /* CL    */ 
#define RPC_PTYPE_NOCALL         0x05 /* CL    */
#define RPC_PTYPE_REJECT         0x06 /* CL    */
#define RPC_PTYPE_ACK            0x07 /* CL    */
#define RPC_PTYPE_CL_CANCEL      0x08 /* CL    */
#define RPC_PTYPE_FACK           0x09 /* CL    */
#define RPC_PTYPE_CANCEL_ACK     0x0a /* CL    */
#define RPC_PTYPE_BIND           0x0b /* CO    */
#define RPC_PTYPE_BIND_ACK       0x0c /* CO    */
#define RPC_PTYPE_BIND_NAK       0x0d /* CO    */
#define RPC_PTYPE_ALTER_CTX      0x0e /* CO    */
#define RPC_PTYPE_ALTER_CTX_RESP 0x0f /* CO    */
#define RPC_PTYPE_SHUTDOWN       0x11 /* CO    */
#define RPC_PTYPE_CO_CANCEL      0x12 /* CO    */
#define RPC_PTYPE_ORPHANED       0x13 /* CO    */

/* PFC FLAGS */
#define PFC_FIRST_FRAG      0x01 /* First fragment. */
#define PFC_LAST_FRAG       0x02 /* Last fragment. */
#define PFC_PENDING_CANCEL  0x04 /* Cancel was pending at sender. */
#define PFC_RESERVED_1      0x08
#define PFC_CONC_MPX        0x10 /* Supports concurrent multiplexing.*/ 
#define PFC_DID_NOT_EXECUTE 0x20 /* Fault packet. */
#define PFC_MAYBE           0x40 /* "Maybe" call semantics requested. */
#define PFC_OBJECT_UUID     0x80 /* A non-nil object UUID is present. */


/* DCE/RPC Endpoint Mapper Protocol. */
/* Reference: pubs.opengroup.org/onlinepubs/009629399/apdxo.htm */

#define EPT_INSERT       0
#define EPT_DELETE       1
#define EPT_LOOKUP       2   /* Lookup entries in an endpoint map. */  
#define EPT_MAP          4
#define EPT_LOOKUP_FREE  5

typedef struct ept_lookup_handle {   
   uint32_t attributes;
   uuid_t   uuid;  
} ept_lookup_handle_t;

/**********************************
typedef struct ndr_context_handle { 
   uint32_t context_handle_attributes;
   uuid_t   context_handle_uuid;
} ndr_context_handle_t;
**********************************/

/* Inquiry types. */
#define RPC_C_EP_ALL_ELTS             0  /* Return all elements from the endpoint map. */
#define RPC_C_EP_MATCH_BY_IF          1
#define RPC_C_EP_MATCH_BY_OBJ         2
#define RPC_C_EP_MATCH_BY_BOTH        3

#define RPC_C_VERS_ALL                1
#define RPC_C_VERS_COMPATIBLE         2
#define RPC_C_VERS_EXACT              3
#define RPC_C_VERS_MAJOR_ONLY         4
#define RPC_C_VERS_UPTO               5
#define RPC_C_ERROR_STRING_LEN      256

#define RPC_C_MGMT_INQ_IF_IDS         0
#define RPC_C_MGMT_INQ_PRINC_NAME     1
#define RPC_C_MGMT_INQ_STATS          2
#define RPC_C_MGMT_IS_SERVER_LISTEN   3
#define RPC_C_MGMT_STOP_SERVER_LISTEN 4

typedef struct ept_lookup {
   uint32_t inquiry_type;
   uint32_t object_referent_id;
   uuid_t   object_uuid;
   uint32_t interface_referent_id; 
   uuid_t   interface_uuid;   
   uint16_t version_major;
   uint16_t version_minor;
   uint32_t vers_option;
   uuid_t   handle; 
   uint32_t max_entries;
} ept_lookup_t;

#define EPT_MAX_ANNOTATION_SIZE 64

typedef struct ept_entry {
   uuid_t object;
   int tower;
   char annotation[EPT_MAX_ANNOTATION_SIZE];
} ept_entry_t, *ept_entry_p_t;


/* Internal "opaque" objects. */
typedef struct buffer {
   void     *data;    /* SND and RCV buffers. */
   size_t   bufsize;  /* Allocated bytes. */
   size_t   offset;   
   size_t   length;   /* Length of the marshalled packet. */   
   int      eof;
   uint32_t index;
} buffer_t;

/* Internal state. */
typedef struct epmap {
   SOCKET sockfd;
   char *server;
   uint16_t port;
   struct sockaddr_in sin;
   buffer_t buffer[2];
   uint32_t call_id;
   uint32_t assoc_group;       /* This is usually ignored. */
   ept_lookup_handle_t handle;
   int state;
   
   p_reject_reason_t reason;   /* Rejection reason code in the bind_nak PDU. */
   uint32_t status;            /* Run-time fault code or zero (fault PDU). */
   int      wsacode;           /* wsa code */
} epmap_t;

/* Error and status codes. $fixme */

#define EPMAP_EOK       0x000 /* Operation completed successfully. */
#define EPMAP_ENOMEM    0x200 /* A call to malloc() failed. */
#define EPMAP_EINVAL    0x201 /* An invalid argument was passed to a library function. */
#define EPMAP_EBADPTR   0x202 /* An invalid pointer was detected. */
#define EPMAP_EWSAINIT  0x203 /* WSAStartup() initialization failed. */
#define EPMAP_EDNSFAIL  0x204 /* Could not resolve host name. */
#define EPMAP_ESOCKET   0x205 /* Could not create socket or connect to server. */
#define EPMAP_ESEND     0x206 /* A call to send() failed. */
#define EPMAP_ERECV     0x207 /* A call to recv() failed. */

#define EPMAP_EACK      0x300 /* BIND-ACK PDU */
#define EPMAP_ENAK      0x301 /* BIND-NAK PDU */
#define EPMAP_EFAULT    0x302 /* Received a FAULT PDU. */
#define EPMAP_EPROTO    0x303 /* Generic protocol error. */
#define EPMAP_ENODATA   0x304 /* Status returned by response $fixme */
                              
#define EPMAP_EDEBUG    0x400



#define EPMAPAPI extern

EPMAPAPI void epmap_destroy(epmap_t *epmap)
{
   buffer_t *buffer = NULL;
   int i;
   
   if (epmap != NULL) {    
       if (epmap->sockfd != INVALID_SOCKET) {
           closesocket(epmap->sockfd);
           WSACleanup();
       }
       for (i = 0; i < 2; i++) {
           buffer = &epmap->buffer[i];
           if (buffer->data != NULL) { 
               buffer->bufsize = 0;
               buffer->length = 0;
               free(buffer->data);   
           }
       }
       free(epmap); 
   }
}

EPMAPAPI epmap_t *epmap_init(size_t snd_len, size_t rcv_len)
{
   epmap_t *epmap = NULL;
   buffer_t *buffer = NULL;
   int i;

   epmap = (epmap_t *)malloc(sizeof(epmap_t));
   if (epmap == NULL) {
       return NULL; 
   }

   epmap->sockfd = INVALID_SOCKET;
   epmap->server = NULL;
   epmap->port = 0;
   epmap->call_id = 0x00000000;

   /* UUID for the ept_lookup_handle generated by the endpoint mapper. */
   epmap->handle.uuid.time_low = 0;
   epmap->handle.uuid.time_mid = 0;
   epmap->handle.uuid.time_hi_and_version = 0; 
   epmap->handle.uuid.clock_seq_hi_and_reserved = 0;
   epmap->handle.uuid.clock_seq_low = 0;
   for (i = 0; i < sizeof(epmap->handle.uuid.node); i++)
       epmap->handle.uuid.node[i] = 0;

   epmap->state = 0;
   epmap->reason = 0;
   epmap->status = 0;
   epmap->wsacode = 0;

   for (i = 0; i < 2; i++) {
       buffer = &epmap->buffer[i]; 
       //////buffer->bufsize = !i ? snd_len : rcv_len;
       buffer->bufsize = 8192;   /* Size of allocated bytes. */

       buffer->data = (void *)malloc(buffer->bufsize);
       if (buffer->data == NULL) {
           epmap_destroy(epmap);
           return NULL;   
       }
       memset(buffer->data, '\0', buffer->bufsize); 
       buffer->length = 0; 
       buffer->offset = 0;
       buffer->eof = 0; 
   }

   return epmap;
}

static int winsock_init(void)
{
   WORD wVersionRequested;
   WSADATA wsaData;
   int error = 0;

   wVersionRequested = MAKEWORD(2, 2);
   error = WSAStartup(wVersionRequested, &wsaData);
   if (error != 0)
       return error;

   /* Confirm that the WinSock DLL supports 2.2. */   
   if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
       WSACleanup();
       return WSAVERNOTSUPPORTED;   
   }    

   return error;   
}

static SOCKET create_socket(const char *server, uint16_t port, struct sockaddr_in *sin, int *ecode)
{
   SOCKET SocketID = INVALID_SOCKET;
   struct addrinfo *result = NULL;
   struct addrinfo *ptr    = NULL;
   struct addrinfo hints;
   int error;
   char szport[5+1];

   memset(&hints, '\0', sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;

   _snprintf(szport, 5, "%u", port); 
   szport[5] = '\0'; /* Redundant. */

   *ecode = 0;

   error = getaddrinfo(server, szport, &hints, &result);
   if (error != 0) {
       *ecode = WSAGetLastError();
       return INVALID_SOCKET;
   }

   for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
       SocketID = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
       if (SocketID == INVALID_SOCKET) {
           *ecode = WSAGetLastError();
           freeaddrinfo(result);
           WSACleanup(); 
           return INVALID_SOCKET;
       } 
       error = connect(SocketID, ptr->ai_addr, (int)ptr->ai_addrlen);
       if (error == SOCKET_ERROR) {
           /* Get WSA error here before closesocket resets it. */ 
           *ecode = WSAGetLastError();
           closesocket(SocketID);
           SocketID = INVALID_SOCKET;
           continue;  
       }  
       break; 
   }

   freeaddrinfo(result);

   if (SocketID == INVALID_SOCKET) 
       return INVALID_SOCKET;
   else {
       int sinlen = sizeof(struct sockaddr_in);  
       getpeername(SocketID, sin, &sinlen);     
   }


   return SocketID;
}

static int epmap_connect(epmap_t *epmap, const char *server, uint16_t port)
{
   int result;

   if (server == NULL || strlen(server) > 128)
       return EPMAP_EINVAL;

   epmap->server = server;
   epmap->port   = port;
   
   /* Initialize Windows Sockets. */
   result = winsock_init();
   if (result != 0) {
       /* Use WSASetLastError? */
       return EPMAP_EWSAINIT; 
   }    

   int ecode;

   epmap->sockfd = create_socket(epmap->server, epmap->port, &epmap->sin, &ecode);
   if (epmap->sockfd == INVALID_SOCKET) {
   
       return ((ecode << 12) | EPMAP_ESOCKET);
   }

   return EPMAP_EOK;
}

static int epmap_send(epmap_t *epmap)
{   
   buffer_t *buffer = &epmap->buffer[0];
   size_t length;
   int n = 0;

   length = buffer->length;
   buffer->offset = 0;

   while (length > 0 && n != SOCKET_ERROR) {
       n = send(epmap->sockfd, (uint8_t *)buffer->data+buffer->offset, length, 0);
       if (n == SOCKET_ERROR) {
           return EPMAP_ESEND;
       }        
       length -= n;
       buffer->offset += n;  
   }
   buffer->length = 0;
   
   return EPMAP_EOK;
}

/* $fixme: Implement a proper finite state machine. */

/*****************
static int _epmap_recv(epmap_t *epmap)
{
   buffer_t *buffer = &epmap->buffer[1];
   int n;
   int bufsize = 0;
   uint8_t *ptr = NULL;
   int length = 8;

   ptr = (uint8_t *)buffer->data + length; 
   
   // Get at least 8 bytes, decode the PDU length to retrieve the rest of
   // the packet. 

   bufsize = buffer->bufsize;
   buffer->length = 0;

   while(length > 0) {
       n = recv(epmap->sockfd, buffer->data, bufsize, 0);
           if (n == SOCKET_ERROR)
               return SOCKET_ERROR;
       buffer->length += n;  Data we have in the buffer. 
       if (buffer->length >= 10) {
            Decode length. 
           if (!flag) {
                
               length = ptr[0] | ((ptr[1] << 8) & 0xff00);
               bufsize = length - buffer->length;  Length of PDU minus what we have buffered.
               flag = 10000;    
           }           
           length -= n;     

            Set new length. 
       } else {
           length -= n;    
       }    
   }
   return buffer->length;
}
*************/

/* This is wrong but it will do, for now. */
static int epmap_recv(epmap_t *epmap)
{
   buffer_t *buffer = &epmap->buffer[1];
   int n;

   n = recv(epmap->sockfd, buffer->data, buffer->bufsize, 0);
   if (n == SOCKET_ERROR) {
       return EPMAP_ERECV; 
   }
   buffer->length = n;

   return EPMAP_EOK;
}

static void w_byte(epmap_t *epmap, unsigned char value)
{
   buffer_t *buffer = &epmap->buffer[0];
   unsigned char *ptr = (unsigned char *)buffer->data;

   buffer->eof = buffer->offset >= buffer->bufsize;

   if (!buffer->eof) {
       ptr += buffer->offset;
       *ptr = value; 
       buffer->offset++;
       ptr = NULL;       
   }   

}

static void ndr_wle8(epmap_t *epmap, uint8_t value)
{
   w_byte(epmap, value);
}

static void ndr_wle16(epmap_t *epmap, uint16_t value)
{
   ndr_wle8(epmap,  value       & 0xff);
   ndr_wle8(epmap, (value >> 8) & 0xff);
}

static void ndr_wle32(epmap_t *epmap, uint32_t value)
{
   ndr_wle8(epmap,  value        & 0xff);
   ndr_wle8(epmap, (value >>  8) & 0xff);
   ndr_wle8(epmap, (value >> 16) & 0xff);
   ndr_wle8(epmap, (value >> 24) & 0xff); 
}

static int r_byte(epmap_t *epmap)
{
   buffer_t *buffer = &epmap->buffer[1];
   unsigned char *ptr = (unsigned char *)buffer->data;
   int value = EOF;

   buffer->eof = buffer->offset >= buffer->length;

   if (!buffer->eof) {
       ptr += buffer->offset;
       value = *ptr;
       buffer->offset++;  
       ptr = NULL; 
   }

   return value;
}

static uint8_t ndr_rle8(epmap_t *epmap)
{
   return (uint8_t)r_byte(epmap);
}

static uint16_t ndr_rle16(epmap_t *epmap)
{
   uint16_t value;

   value  = (uint16_t)ndr_rle8(epmap)        & 0x00ff;
   value |= ((uint16_t)ndr_rle8(epmap) << 8) & 0xff00;

   return value;
}

static uint32_t ndr_rle32(epmap_t *epmap)
{
   uint32_t value;

   value  = (uint32_t)ndr_rle8(epmap)         & 0x000000ff;
   value |= ((uint32_t)ndr_rle8(epmap) <<  8) & 0x0000ff00;
   value |= ((uint32_t)ndr_rle8(epmap) << 16) & 0x00ff0000;
   value |= ((uint32_t)ndr_rle8(epmap) << 24) & 0xff000000;

   return value;
}

static int buffer_seek(epmap_t *epmap, int index, size_t offset, int whence)
{
   buffer_t *buffer = NULL;

   if (index != 0 && index != 1)
       return EPMAP_EINVAL;

   buffer = &epmap->buffer[index];
   buffer->eof = 0;

   if (whence == SEEK_SET) {
       buffer->offset = offset;
   } else if (whence == SEEK_CUR) {
       buffer->offset += offset;
   }  

   return EPMAP_EOK;
}

static int buffer_rewind(epmap_t *epmap)
{   
   buffer_t *buffer = &epmap->buffer[0];
   buffer->offset = 0;

   return buffer_seek(epmap, 0, 0, SEEK_SET);   
}

static size_t buffer_tell(epmap_t *epmap)
{
   buffer_t *buffer = &epmap->buffer[0];

   return buffer->offset;  
}

int ndr_encode_uuid(epmap_t *epmap, const uuid_t *uuid)
{
   int i;

   ndr_wle32(epmap, uuid->time_low);
   ndr_wle16(epmap, uuid->time_mid);
   ndr_wle16(epmap, uuid->time_hi_and_version);
   ndr_wle8(epmap, uuid->clock_seq_hi_and_reserved); 
   ndr_wle8(epmap, uuid->clock_seq_low);
   
   for (i = 0; i < sizeof(uuid->node); i++)
       w_byte(epmap, uuid->node[i]);
   
   return 0;
}

static int ndr_decode_uuid(epmap_t *epmap, uuid_t *uuid)
{
   int i;

   uuid->time_low = ndr_rle32(epmap);
   uuid->time_mid = ndr_rle16(epmap);
   uuid->time_hi_and_version = ndr_rle16(epmap);
   uuid->clock_seq_hi_and_reserved = ndr_rle8(epmap);
   uuid->clock_seq_low = ndr_rle8(epmap);
   
   for (i = 0; i < sizeof(uuid->node); i++)
       uuid->node[i] = r_byte(epmap);

   return EPMAP_EOK;
}

static unsigned long _strtoul(const char *str, size_t length)
{
   unsigned long value = 0;
   int nibble;
   int i;

   for (i = 0; i < length; i++) {
       if (*str >= 0x41 && *str <= 0x46)
           nibble = *str - 0x41 + 0x0a;
       else if (*str >= 0x61 && *str <= 0x66)
           nibble = *str - 0x61 + 0x0a;
       else if (*str >= 0x30 && *str <= 0x39)
           nibble = *str - 0x30;
       else
           return value;

       value = value << 4;
       value |= nibble;
       str++;  
   }

   return value;
}

/* Example: "c9ac6db5-82b7-4e55-ae8a-e464ed7b4277" */
static size_t epmap_string_to_uuid(uuid_t *uuid, const char *string)
{
   const char *ptr = string;
   size_t length;
   int i;

   /* Check whether the string length is sensible. */
   if (strlen(ptr) != 36)
       return 0; 

   length = sizeof(uuid->time_low) << 1;
   uuid->time_low = _strtoul(ptr, length);
   ptr += length;

   if (*ptr++ != '-')
       return 0;

   length = sizeof(uuid->time_mid) << 1;
   uuid->time_mid = _strtoul(ptr, length);
   ptr += length;

   if (*ptr++ != '-')
       return 0;

   length = sizeof(uuid->time_hi_and_version) << 1;
   uuid->time_hi_and_version = _strtoul(ptr, length);
   ptr += length;
   
   if (*ptr++ != '-')
       return 0;

   length = sizeof(uuid->clock_seq_hi_and_reserved) << 1;
   uuid->clock_seq_hi_and_reserved = _strtoul(ptr, length);
   ptr += length;
   length = sizeof(uuid->clock_seq_low) << 1;
   uuid->clock_seq_low = _strtoul(ptr, length);
   ptr += length;  

   if (*ptr++ != '-')
       return 0;

   for (i = 0; i < sizeof(uuid->node); i++) {
       uuid->node[i] = _strtoul(ptr, sizeof(uuid->node[i]) << 1);
       ptr += sizeof(uuid->node[i]) << 1;
   }

   return (size_t)(ptr - string);
}


static int uuid_is_nil(uuid_t *uuid)
{
   return (uuid->time_low == 0 && uuid->time_mid == 0 &&
           uuid->time_hi_and_version == 0 && 
           uuid->clock_seq_hi_and_reserved == 0 && 
           uuid->clock_seq_low == 0 &&
           uuid->node[0] == 0 && uuid->node[1] == 0 && 
           uuid->node[2] == 0 && uuid->node[3] == 0 &&
           uuid->node[4] == 0 && uuid->node[5] == 0);    
}


static int uuid_compare(uuid_t *uuid1, uuid_t *uuid2)
{
   return !(uuid1->time_low == uuid2->time_low && 
            uuid1->time_mid == uuid2->time_mid &&
            uuid1->time_hi_and_version == uuid2->time_hi_and_version &&
            uuid1->clock_seq_hi_and_reserved == uuid2->clock_seq_hi_and_reserved &&
            uuid1->clock_seq_low == uuid2->clock_seq_low &&
            uuid1->node[0] == uuid2->node[0] && 
            uuid1->node[1] == uuid2->node[1] &&
            uuid1->node[2] == uuid2->node[2] &&
            uuid1->node[3] == uuid2->node[3] &&
            uuid1->node[4] == uuid2->node[4] &&
            uuid1->node[5] == uuid2->node[5]);
}

/* Encode the BIND PDU to be sent to the endpoint portmapper. */
static int epmap_encode_bind(epmap_t *epmap, rpcconn_bind_hdr_t *bind)
{
   buffer_t *buffer = &epmap->buffer[0];
   p_cont_elem_t *p_cont_elem = NULL;
   p_syntax_id_t *syntax = NULL;
   uuid_t *uuid = NULL;
   int i, j;
   
   buffer_rewind(epmap);

   ndr_wle8(epmap, bind->rpc_vers);
   ndr_wle8(epmap, bind->rpc_vers_minor);
   ndr_wle8(epmap, bind->ptype);
   ndr_wle8(epmap, bind->pfc_flags);
 
   for (i = 0; i < sizeof(bind->packed_drep); i++)
       w_byte(epmap, bind->packed_drep[i]);

   ndr_wle16(epmap, bind->frag_length);
   ndr_wle16(epmap, bind->auth_length);
   ndr_wle32(epmap, bind->call_id);

   ndr_wle16(epmap, bind->max_xmit_frag);
   ndr_wle16(epmap, bind->max_recv_frag);
   ndr_wle32(epmap, bind->assoc_group_id);

   ndr_wle8(epmap, bind->p_context_elem.n_context_elem); 
   ndr_wle8(epmap, bind->p_context_elem.reserved);
   ndr_wle16(epmap, bind->p_context_elem.reserved2);
   
   for (i = 0; i < bind->p_context_elem.n_context_elem; i++) {

       p_cont_elem = &bind->p_context_elem.p_cont_elem[i];
       ndr_wle16(epmap, p_cont_elem->p_cont_id);
       ndr_wle8(epmap, p_cont_elem->n_transfer_syn);
       ndr_wle8(epmap, p_cont_elem->reserved);  
       uuid = &p_cont_elem->abstract_syntax.if_uuid;
       ndr_encode_uuid(epmap, uuid);           
       ndr_wle32(epmap, p_cont_elem->abstract_syntax.if_version);
       
       for (j = 0; j < p_cont_elem->n_transfer_syn; j++) {
           uuid = &p_cont_elem->transfer_syntaxes[j].if_uuid;
           ndr_encode_uuid(epmap, uuid);      
           ndr_wle32(epmap, p_cont_elem->transfer_syntaxes[j].if_version);
       }
   }

   buffer->length = buffer_tell(epmap);

   /* Make sure we haven't attempted to write beyond the end. */
   if (buffer->eof)
       return 0;

   /* Encode the correct PDU length. */
   buffer->offset = 8;
   ndr_wle16(epmap, buffer->length);

   return buffer->length; 
}

/* Decode the BIND ACK PDU. 
 * The server should accept, at most, one of the transfer syntaxes. If one of
 * the client proposed transfer syntaxes matches the server's preferred transfer
 * syntax, then that syntax is accepted. 
 */
static int epmap_decode_bind_ack(epmap_t *epmap)
{
   rpcconn_bind_ack_hdr_t ack;
   p_result_t *ctx_result = NULL;
   p_syntax_id_t *syntax = NULL;
   buffer_t *buffer = &epmap->buffer[1];
   int i;

   buffer->offset = 0;

   ack.rpc_vers = ndr_rle8(epmap);
   ack.rpc_vers_minor = ndr_rle8(epmap);
   ack.ptype = ndr_rle8(epmap); 

   if (ack.ptype != RPC_PTYPE_BIND_ACK)
       return EPMAP_EPROTO;

   ack.pfc_flags = ndr_rle8(epmap);

   for (int i = 0; i < 4; i++) 
       ack.packed_drep[i] = ndr_rle8(epmap);
   
   ack.frag_length = ndr_rle16(epmap);

   if (ack.frag_length != buffer->length)
       return EPMAP_EPROTO;

   ack.auth_length = ndr_rle16(epmap);
   ack.call_id = ndr_rle32(epmap);

   if (ack.call_id != epmap->call_id)
       return EPMAP_EPROTO;    

   ack.max_xmit_frag = ndr_rle16(epmap);
   ack.max_recv_frag = ndr_rle16(epmap);
   /* The assoc_group ID is not really used for anything useful here. */
   epmap->assoc_group = ack.assoc_group_id = ndr_rle32(epmap);
   
   ack.sec_addr.length = ndr_rle16(epmap);

   /* Skip the ASCII encoded representation of the local port. */
   buffer->offset += ack.sec_addr.length;
    
   /* Skip padding bytes to restore the 4-octet alignment. */
   /* Note that padding bytes need not be zero. */
   while ((buffer->offset % 4) != 0)
       r_byte(epmap);
   
   ack.p_result_list.n_results = ndr_rle8(epmap);
   ack.p_result_list.reserved = ndr_rle8(epmap);
   ack.p_result_list.reserved2 = ndr_rle8(epmap);

   /////printf("Results: %u \n", ack.p_result_list.n_results);

   ack.p_result_list.p_results = malloc(sizeof(p_result_t) * ack.p_result_list.n_results);
   if (ack.p_result_list.p_results == NULL) {  
       printf("Memory allocation failed");
       return EPMAP_ENOMEM; /* $fixme */
   }

   for (i = 0; i < ack.p_result_list.n_results; i++) {
       ctx_result = &ack.p_result_list.p_results[i];
       ctx_result->result = ndr_rle16(epmap);
       /* Reason is relevant only if result != acceptance (0). */ 
       ctx_result->reason = ndr_rle16(epmap);      
       syntax = &ctx_result->transfer_syntax;
       ndr_decode_uuid(epmap, &syntax->if_uuid);
       syntax->if_version = ndr_rle32(epmap);
       if (ctx_result->result != 0) {
            /* Do nothing, for now. */
       }
   }
   free(ack.p_result_list.p_results);

   return EPMAP_EOK;
}

/* Decode the BIND NAK PDU. */
static int epmap_decode_bind_nak(epmap_t *epmap)
{
   rpcconn_bind_nak_hdr_t nak;
   buffer_t *buffer = &epmap->buffer[1];

   buffer->offset = 0;

   nak.rpc_vers = ndr_rle8(epmap);
   nak.rpc_vers_minor = ndr_rle8(epmap); 
   nak.ptype = ndr_rle8(epmap);

   if (nak.ptype != RPC_PTYPE_BIND_NAK)
       return EPMAP_EPROTO;  

   nak.pfc_flags = ndr_rle8(epmap);

   for (int i = 0; i < sizeof(nak.packed_drep); i++)
       nak.packed_drep[i] = ndr_rle8(epmap);

   nak.frag_length = ndr_rle16(epmap);
   if (nak.frag_length != buffer->length)
       return EPMAP_EPROTO;

   nak.auth_length = ndr_rle16(epmap);
   nak.call_id = ndr_rle32(epmap);

   /* Should it be reason? */
   epmap->reason = nak.provider_reject_reason = ndr_rle16(epmap);
   
   /* Array of protocol versions supported, ignored. */
   nak.versions = NULL; 

   return EPMAP_EOK;
}


/*****************
int epmap_decode_alter_context(epmap_t *epmap)
{
   buffer_t *buffer = &epmap->buffer[1];
   buffer_rewind(epmap);
   return 0;
}
**********************/


/* Send a BIND request to the server.  */
EPMAPAPI int epmap_bind(epmap_t **epmap, const char *server, uint16_t port)
{
   rpcconn_bind_hdr_t bind;
   p_cont_elem_t *p_cont_elem = NULL;
   uuid_t *uuid = NULL; 
   p_syntax_id_t *syntax = NULL;
   int ptype;
   int result;
   int n;

   if (server == NULL || strlen(server) == 0)
       return EPMAP_EINVAL; 
 
   /* Initialize the EPMAP object. */
   *epmap = epmap_init(8192, 8192);
   if (*epmap == NULL)
       return EPMAP_ENOMEM;     

    (*epmap)->server = server;
    (*epmap)->port   = port;

   /* Connect to server. */
   result = epmap_connect(*epmap, (*epmap)->server, (*epmap)->port);   
   if (result != EPMAP_EOK) {
       /* Contains winsock error. */
       /////result |= (WSAGetLastError() << 12); /* Winsock error. */

       epmap_destroy(*epmap);  
       return result;
   }

  
   
   /* Populate the bind request. */
   bind.rpc_vers = 5;
   bind.rpc_vers_minor = 0;
   bind.ptype = RPC_PTYPE_BIND;
   bind.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG; /* 0x03 */

   /* Data representation format label. */
   bind.packed_drep[0] = 0x10; /* Byte order: Little-endian; Charset: ASCII. */
   bind.packed_drep[1] = 0x00; /* Floating-point: IEEE 754. */
   bind.packed_drep[2] = 0x00; /* Reserved for future use. */
   bind.packed_drep[3] = 0x00; /* Reserved for future use. */
   
   bind.frag_length = 0; /* Must be 116, but we set it within the encoding function. */
   bind.auth_length = 0;
   (*epmap)->call_id = bind.call_id = 1;

   bind.max_xmit_frag = 5840;
   bind.max_recv_frag = 5840;
   bind.assoc_group_id = 0;

   /* Presentation context list. */  

   n = bind.p_context_elem.n_context_elem = 2;
   bind.p_context_elem.reserved = 0;
   bind.p_context_elem.reserved2 = 0;

   bind.p_context_elem.p_cont_elem = malloc(sizeof(p_cont_elem_t) * n);
   if (bind.p_context_elem.p_cont_elem == NULL) {
       epmap_destroy(*epmap);
       return EPMAP_ENOMEM;
   }

   /**** Element in the presentation context list, item #1 ****/
   p_cont_elem = &bind.p_context_elem.p_cont_elem[0];

   p_cont_elem->p_cont_id = 0x0000;
   p_cont_elem->n_transfer_syn = 1;
   p_cont_elem->reserved = 0;

   /* Abstract Syntax: EPMv4 v3.0. */
   /* It will be encoded into memory as:              */
   /* 08 83 af e1 1f 5d c9 11 91 A4 08 00 2b 14 a0 fa */                               
   uuid = &p_cont_elem->abstract_syntax.if_uuid;
   epmap_string_to_uuid(uuid, "e1af8308-5d1f-11c9-91a4-08002b14a0fa");
   p_cont_elem->abstract_syntax.if_version = 3;                        

   p_cont_elem->transfer_syntaxes = malloc(sizeof(p_syntax_id_t) * 1);
   if (p_cont_elem->transfer_syntaxes == NULL) {
       epmap_destroy(*epmap); 
       free(bind.p_context_elem.p_cont_elem);
       return EPMAP_ENOMEM;  
   }

   syntax = &p_cont_elem->transfer_syntaxes[0];

   /* Transfer Syntax: 32-bit NDR v2.0 */
   /* Reference: pubs.opengroup.org/onlinepubs/9629399/apdxi.htm  */
   uuid = &syntax->if_uuid;
   epmap_string_to_uuid(uuid, "8a885d04-1ceb-11c9-9fe8-08002b104860");
   syntax->if_version = 2;

   /**** Element in the presentation context list, item #2 ****/
   p_cont_elem = &bind.p_context_elem.p_cont_elem[1];

   p_cont_elem->p_cont_id = 0x0001;
   p_cont_elem->n_transfer_syn = 1;
   p_cont_elem->reserved = 0;

   /* Abstract Syntax: EPMv4 v3.0. */
   uuid = &p_cont_elem->abstract_syntax.if_uuid;
   epmap_string_to_uuid(uuid, "e1af8308-5d1f-11c9-91a4-08002b14a0fa");
   p_cont_elem->abstract_syntax.if_version = 3;                        
    
   p_cont_elem->transfer_syntaxes = malloc(sizeof(p_syntax_id_t) * 1);
   if (p_cont_elem == NULL) {
       epmap_destroy(*epmap); 
       free(bind.p_context_elem.p_cont_elem[0].transfer_syntaxes);
       free(bind.p_context_elem.p_cont_elem);
       return EPMAP_ENOMEM;
   }

   syntax = &p_cont_elem->transfer_syntaxes[0];

   /* Transfer Syntax: Bind time feature negotiation v1. */
   uuid = &syntax->if_uuid;
   epmap_string_to_uuid(uuid, "6cb71c2c-9812-4540-0300-000000000000");  
   syntax->if_version = 1;

    /* Encode the bind request. */
   epmap_encode_bind(*epmap, &bind);

   free(bind.p_context_elem.p_cont_elem[0].transfer_syntaxes);
   free(bind.p_context_elem.p_cont_elem[1].transfer_syntaxes);
   free(bind.p_context_elem.p_cont_elem);
 
   /* Send the bind request. */   
   result = epmap_send(*epmap);
   if (result != EPMAP_EOK) {
       result |= (WSAGetLastError() << 12); 
       epmap_destroy(*epmap); 
       return result;
   }

   result = epmap_recv(*epmap);
   if (result != EPMAP_EOK) {
       result != (WSAGetLastError() << 12);
       epmap_destroy(*epmap);
       return result;
   }

   /* Retrieve the ptype field. */
   buffer_seek(*epmap, 1, 2, SEEK_SET); 
   ptype = ndr_rle8(*epmap); 

   switch(ptype) {
       case RPC_PTYPE_BIND_ACK:
           result = epmap_decode_bind_ack(*epmap);
           if (result != EPMAP_EOK)
               epmap_destroy(*epmap);
           break; 
       case RPC_PTYPE_BIND_NAK:
           result = epmap_decode_bind_nak(*epmap); 
           /* Return the reason. */
           result = ((((*epmap)->reason) << 12) & 0xfff) | EPMAP_ENAK; 
           epmap_destroy(*epmap);
           break;   
       default:
           /* Not a valid RPC PDU, wrong protocol? */ 
           result = EPMAP_EPROTO;
           epmap_destroy(*epmap);
           break; 
   }

   return result;    
}

static int epmap_encode_request(epmap_t *epmap, const rpcconn_request_hdr_t *request, const ept_lookup_t *ept_lookup)
{
   size_t length;
   buffer_t *buffer = &epmap->buffer[0];
   int i;

   buffer_seek(epmap, 0, 0, SEEK_SET); /* buffer_rewind(epmap) */
   
   ndr_wle8(epmap, request->rpc_vers);
   ndr_wle8(epmap, request->rpc_vers_minor);
   ndr_wle8(epmap, request->ptype);
   ndr_wle8(epmap, request->pfc_flags);

   for (i = 0; i < sizeof(request->packed_drep); i++)
       w_byte(epmap, request->packed_drep[i]);

   ndr_wle16(epmap, request->frag_length);
   ndr_wle16(epmap, request->auth_length);
   ndr_wle32(epmap, request->call_id);

   ndr_wle32(epmap, request->alloc_hint);
   ndr_wle16(epmap, request->p_cont_id);
   ndr_wle16(epmap, request->opnum);

   /* Stub data, aligned to an 8-octet boundary. */
   /* PortQry always generates 76 bytes. */

   ndr_wle32(epmap, ept_lookup->inquiry_type);  /* rpc_c_ep_all_elts */

   ndr_wle32(epmap, ept_lookup->object_referent_id); 
   ndr_encode_uuid(epmap, &ept_lookup->object_uuid); 

   ndr_wle32(epmap, ept_lookup->interface_referent_id); 
   ndr_encode_uuid(epmap, &ept_lookup->interface_uuid); 

   ndr_wle16(epmap, ept_lookup->version_major);
   ndr_wle16(epmap, ept_lookup->version_minor);
   
   ndr_wle32(epmap, 0); /* Version Option, or Attributes. */

    /* UUID Handle */

   ndr_wle32(epmap, epmap->handle.attributes); /* Something preceding the UUID. */
   
   ndr_encode_uuid(epmap, &epmap->handle.uuid);
  
   /* Max entries */
   ndr_wle32(epmap, 1);
   
   /* Encode the correct length. */

   buffer->length = buffer_tell(epmap);

   if (buffer->eof)
       return 0;

   buffer->offset = 8;  
   ndr_wle16(epmap, buffer->length); 

   return buffer->length;
}


typedef struct tower_entry {
   unsigned int proto_id;
   uint16_t tcp_port;
   uint16_t udp_port;
   uint32_t host_addr;
   char named_pipe[128];
   //////char netbios_name[16];
} tower_entry_t;

/* Protocol identifiers. */
#define PROTO_ID_OSI_OID        0x00 /* OSI OID */
#define PROTO_ID_DNA_SESSCTL    0x02 /* DNA Session Control */
#define PROTO_ID_DNA_SESSCTL_V3 0x03 /* DNA Session Control V3 */
#define PROTO_ID_DNA_NSP        0x04 /* DNA NSP Transport */
#define PROTO_ID_OSI_TP4        0x05 /* OSI TP4 */
#define PROTO_ID_OSI_CLNS       0x06 /* OSI CLNS or DNA Routing */  
#define PROTO_ID_TCP            0x07 /* DOD TCP, 16-bit unsigned, big-endian */
#define PROTO_ID_UDP            0x08 /* DOD UDP, 16-bit unsigned, big-endian */
#define PROTO_ID_IP             0x09 /* DOD IP */
#define PROTO_ID_RPC_CL         0x0a /* RPC Connectionless Protcol */
#define PROTO_ID_RPC_CO         0x0b /* RPC Connection-Oriented Protocol */    
#define PROTO_ID_SPX            0x0c /* Netware SPX ??? */
#define PROTO_ID_UUID           0x0d /* UUID */
#define PROTO_ID_IPX            0x0e /* Netware IPX ???  */
#define PROTO_ID_NAMED_PIPES    0x0f /* Microsoft Named Pipes */
#define PROTO_ID_NAMED_PIPES_2  0x10 /* Microsoft Named Pipes (SMB?) */   
#define PROTO_ID_NETBIOS        0x11 /* Microsoft NetBIOS */
#define PROTO_ID_NETBEUI        0x12 /* Microsoft NetBEUI */ 
#define PROTO_ID_NETWARE_SPX    0x13 /* Netware SPX transport-layer protocol */
#define PROTO_ID_NETWARE_IPX    0x14 /* Netware IPX transport-layer protocol */
#define PROTO_ID_ATALK_STREAM   0x16 /* Appletalk Stream */
#define PROTO_ID_ATALK_DATAGRAM 0x17 /* Appletalk Datagram */
#define PROTO_ID_ATALK          0x18 /* Appletalk */ 
#define PROTO_ID_NETBIOS_2      0x19 /* NetBIOS, CL over all protocols */
#define PROTO_ID_VINES_SPP      0x1a /* Vines SPP */
#define PROTO_ID_VINES_IPC      0x1b /* Vines IPC */
#define PROTO_ID_STREETTALK     0x1c /* StreetTalk name */
#define PROTO_ID_HTTP           0x1f /* RPC over HTTP */         
#define PROTO_ID_UNIX_DOMAIN    0x20 /* Unix Domain socket */
#define PROTO_ID_NULL           0x21 /* NULL */
#define PROTO_ID_NETBIOS_3      0x22 /* NetBIOS */

/* Reference: pubs.opengroup.org/onlinepubs/9629399/apdxb.htm */
struct proto_sequence {
   unsigned int proto_id;   
   const char *string;
} proto_seq[] = {
    PROTO_ID_TCP,           "ncacn_ip_tcp",
    PROTO_ID_UDP,           "ncacn_ip_udp",
    PROTO_ID_IP,            "ncacn_ip_ip",
    PROTO_ID_NAMED_PIPES,   "ncacn_np", 
    PROTO_ID_NAMED_PIPES_2, "ncacn_np"  
};

static const char *proto_sequence_string(int proto_id)
{
   const char *str = "unknown";
   int i;
   
   for (i = 0; i < 5; i++) {
       if (proto_id == proto_seq[i].proto_id)
           str = proto_seq[i].string; 
   }

   return str;           
}

static int epmap_decode_response(epmap_t *epmap, tower_entry_t *tower, uuid_t *uuid, char *annot)
{
   rpcconn_response_hdr_t response;
   ept_lookup_t ept_lookup; 
   buffer_t *buffer = &epmap->buffer[1];
   uuid_t object_uuid;
   int annot_offset;
   int annot_len;
   unsigned int proto_id;
   uint8_t *ptr = NULL;
   int floor_count;
   int lhslen, rhslen;
   int i, j;
   unsigned long x;
   
   buffer->offset = 0;
   memset(annot, '\0', EPT_MAX_ANNOTATION_SIZE);
   ptr = (uint8_t *)buffer->data + buffer->offset;
   
   response.rpc_vers = ndr_rle8(epmap);
   response.rpc_vers_minor = ndr_rle8(epmap);
   response.ptype = ndr_rle8(epmap);
   response.pfc_flags = ndr_rle8(epmap);
  
   for (int i = 0; i < sizeof(response.packed_drep); i++)
       response.packed_drep[i] = ndr_rle8(epmap);

   response.frag_length = ndr_rle16(epmap);
   response.auth_length = ndr_rle16(epmap);
   response.call_id = ndr_rle32(epmap);
   response.alloc_hint  = ndr_rle32(epmap);
   response.p_cont_id = ndr_rle16(epmap);
   response.cancel_count = ndr_rle8(epmap);
   response.reserved = ndr_rle8(epmap);

   /* Stub data (opnum == EPT_LOOKUP). */

   /* Is this always zero? */
   epmap->handle.attributes = ndr_rle32(epmap); 
      
   /* Extract the interface UUID and use it for next requests. */

   /* On the first call, the client must set the entry_handle to NULL. 
    * On subsequent calls, the client will use the context handle returned.   
    */
    
   if (uuid_is_nil(&epmap->handle.uuid))
       ndr_decode_uuid(epmap, &epmap->handle.uuid);
   else /* We already have an handle. */
       buffer->offset += 16;

   /* Num entries entry_count. This is either 1 or 0. */
   int num = ndr_rle32(epmap);

   /* Max count. */
   ndr_rle32(epmap);
   /* Offset. */
   ndr_rle32(epmap);
   /* Actual count. */
   ndr_rle32(epmap);   

   for (i = 0; i < num; i++) {

       ndr_decode_uuid(epmap, &object_uuid);

       ////if (uuid_compare(&epmap->handle.uuid, &object_uuid) != 0)
       /////    printf("Error \n");



       /* Referent ID */
       ndr_rle32(epmap);  
    
       /* Annotation */
       annot_offset = ndr_rle32(epmap);  
       annot_len = ndr_rle32(epmap); 
    
       /* Copy into annotation */   
       if (annot_len <= EPT_MAX_ANNOTATION_SIZE) {   
           memcpy(annot, ptr + buffer->offset, annot_len);
       }

       /* Skip the annotation. */
       buffer->offset += annot_len;

       /* Restore alignment. */   
       while ((buffer->offset % 4) != 0) 
           buffer->offset++;

       /* Tower length. Skip. */
       buffer->offset += 8;   

       /* Floor count */
       /* The LHS of the floor contains protocol identifier information.     */
       /* The RHS of the floor contains related or addressing information.   */
       /* The content of floor 4 and 5 are protoseq-specific. The layout is: */
       /* Floor 1 - RPC interface identifier                                 */ 
       /* Floor 2 - RPC Data representation identifier                       */
       /* Floor 3 - RPC protocol identifier                                  */
       /* Floor 4 - Port address (for ncacn_ip_tcp and ncadg_ip_udp)         */
       /* Floor 5 - Host address (for ncacn_ip_tcp and ncadg_ip_udp)         */

       /* Floors */
       floor_count = ndr_rle16(epmap);

       tower->proto_id = 0; 
       tower->tcp_port = 0;
       tower->udp_port = 0;
       tower->host_addr = 0;
       memset(tower->named_pipe, '\0', sizeof(tower->named_pipe));

       for (j = 0; j < floor_count; j++) {

           lhslen = ndr_rle16(epmap);
           proto_id = ndr_rle8(epmap); 

           switch(proto_id) {
               case PROTO_ID_TCP:    /* 0x07 */
                   buffer->offset += lhslen - 1;
                   rhslen = ndr_rle16(epmap);
                   x = ndr_rle16(epmap);
                   tower->tcp_port = ((x >> 8) & 0xff) | ((x << 8) & 0xff00);
                   break;

               case PROTO_ID_UDP:    /* 0x08 */ 
                   buffer->offset += lhslen - 1;
                   rhslen = ndr_rle16(epmap);
                   x = ndr_rle16(epmap);
                   tower->udp_port = ((x >> 8) & 0xff) | ((x << 8) & 0xff00);
                   break; 

               case PROTO_ID_IP:     /* 0x09 */
                   buffer->offset += lhslen - 1; 
                   rhslen = ndr_rle16(epmap);
                   tower->host_addr = ndr_rle32(epmap);  
                   break;   

               case PROTO_ID_RPC_CL: /* 0x0a */
                   buffer->offset += lhslen - 1;
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;
                   break;

               case PROTO_ID_RPC_CO: /* RPC connection-oriented protocol */
                   /* LHS Length: 1 */
                   buffer->offset += lhslen - 1; 
                   /* RHS Length: 2, usually 0x0000. */
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;
                   break; 

               case PROTO_ID_SPX: /* SPX ??? */
                   /* LHS Length: 1 */
                   buffer->offset += lhslen - 1;
                   /* RHS Length: 2, usually 0x0000. */ 
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;
                   break;
              
               case PROTO_ID_UUID: /* 0x0d */  
                   if (j == 0)
                       ndr_decode_uuid(epmap, uuid);
                   else
                       buffer->offset += 16; 
                   /* Version */
                   ndr_rle16(epmap);
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;                   
                   break;
    
               case PROTO_ID_NAMED_PIPES: /* 0x0f */
                   /* LHS Length: 1 */
                   buffer->offset += lhslen - 1;
                   /* nul-terminated string */
                   rhslen = ndr_rle16(epmap);
                   tower->proto_id = proto_id;
                   memcpy(tower->named_pipe, (uint8_t *)buffer->data + buffer->offset, rhslen);
                   buffer->offset += rhslen; 
                   break;  

               case PROTO_ID_NAMED_PIPES_2: /* 0x10 */ 
                   /* Don't print these, they never have annotations. */
                   /* LHS Length: 1 */
                   buffer->offset += lhslen - 1;
                   /* nul-terminated string  */ 
                   rhslen = ndr_rle16(epmap);
                   memcpy(tower->named_pipe, (uint8_t *)buffer->data + buffer->offset, rhslen);
                   buffer->offset += rhslen;
                   break;

               case 0x11: /* NETBIOS */
                   /* LHS Length: 1 */
                   buffer->offset += lhslen - 1;
                   /* nul-terminated string */
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;
                   break;

               default: /* Unknown Protocol ??? */
                   buffer->offset += lhslen - 1;
                   rhslen = ndr_rle16(epmap);
                   buffer->offset += rhslen;    
                   break;    

           } /* switch() */
       } /* for() loop */
   }  /* for() loop */


   /* Restore 4-octet alignment. */
   while ((buffer->offset % 4) != 0) 
           buffer->offset++;
    
   /* The status code could be either zero or 0x16c9a0cd. 
    * 0x00000000: The method call returned at least one element that matched
    * the search criteria. 
    * 0x16c9a0d6: The are no elements that satisfy the specified search criteria.
    * This is normally returned when there are no more entries.  
    */
  
   /* $fixme */

   uint32_t status;

   epmap->status = status = ndr_rle32(epmap);

   return status; /* $fixme return EPMAP_EOK */
}

static int epmap_decode_fault(epmap_t *epmap)
{
   rpcconn_fault_hdr_t fault;
   buffer_t *buffer = &epmap->buffer[1];
   int i;

   buffer->offset = 0;

   fault.rpc_vers = ndr_rle8(epmap);
   fault.rpc_vers_minor = ndr_rle8(epmap);
   fault.ptype = ndr_rle8(epmap);
   fault.pfc_flags = ndr_rle8(epmap);

   for (i = 0; i < sizeof(fault.packed_drep); i++)
       fault.packed_drep[i] = ndr_rle8(epmap);
    
   fault.frag_length = ndr_rle16(epmap);
   fault.auth_length = ndr_rle16(epmap);
   fault.call_id = ndr_rle32(epmap);
   fault.alloc_hint = ndr_rle32(epmap);
   fault.p_cont_id = ndr_rle16(epmap);
   fault.cancel_count = ndr_rle8(epmap);
   fault.reserved = ndr_rle8(epmap);

   /* Status can be */
   fault.status = ndr_rle32(epmap);
   /* 4 bytes of padding here? */

   return 0;
}


static int epmap_encode_shutdown(epmap_t *epmap, rpcconn_shutdown_hdr_t *shutdown)
{
 
   buffer_t *buffer = &epmap->buffer[0];
   /******************************
   int i;
      
   buffer_seek(epmap, 0, 0, SEEK_SET);
 
   ndr_wle8(epmap, shutdown->rpc_vers);  
   ndr_wle8(epmap, shutdown->rpc_vers_minor);
   ndr_wle8(epmap, shutdown->ptype);
   ndr_wle8(epmap, shutdown->pfc_flags);

   for (i = 0; i < sizeof(bind->packed_drep); i++)
       w_byte(epmap, shutdown->packed_drep[i]; 

   ndr_wle16(epmap, shutdown->frag_length);
   ndr_wle16(epmap, shutdown->auth_length);
   ndr_wle32(epmap, shutdown->call_id); 

   buffer->length = buffer_tell(epmap);

   if (buffer->eof)
       return 0;
 
   ////// Encode the correct PDU length.
   buffer->offset = 8;   
   ndr_wle16(epmap, buffer->length);

   *********************************************/

   return buffer->length;
} 

/* Encode and send shutdown? */
static int epmap_shutdown(epmap_t *epmap)
{
   rpcconn_shutdown_hdr_t shutdown;
   int result;

   shutdown.rpc_vers = 5;
   shutdown.rpc_vers_minor = 0;
   shutdown.ptype = RPC_PTYPE_SHUTDOWN;
   shutdown.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;

   shutdown.packed_drep[0] = 0x10;
   shutdown.packed_drep[1] = 0x00;
   shutdown.packed_drep[2] = 0x00;
   shutdown.packed_drep[3] = 0x00;

   /* Must be ... */
   shutdown.frag_length = 0;
   /* The shutdown PDU never contains an authentication verifier. */
   shutdown.auth_length = 0; 
   shutdown.call_id = epmap->call_id; 

   epmap_encode_shutdown(epmap, &shutdown);  
   
   /* Send shutdown PDU. $fixme 
   result = epmap_send(epmap); 
   if (result != EPMAP_EOK) {
       result |= (WSAGetLastError() << 12);
       return result;
   } 
 
   */
   
   closesocket(epmap->sockfd);
   epmap->sockfd = INVALID_SOCKET;
   WSACleanup();   

   return 0;
}


/* epmap_request */
static int epmap_request(epmap_t *epmap, tower_entry_t *tower, uuid_t *uuid, char *annot)
{
   rpcconn_request_hdr_t request;
   ept_lookup_t ept_lookup;
   uuid_t *p_uuid = NULL;
   int ptype;
   int result;

   if (epmap == NULL || uuid == NULL)
       return EPMAP_EINVAL;

   /* Populate the request. */
   request.rpc_vers = 5;
   request.rpc_vers_minor = 0;
   request.ptype = RPC_PTYPE_REQUEST;
   request.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG; /* 0x03 */

   request.packed_drep[0] = 0x10; /* Byte order: Little-endian; Charset: ASCII. */
   request.packed_drep[1] = 0x00; /* Floating-point: IEEE 754.*/
   request.packed_drep[2] = 0x00; /* Reserved for future use. */
   request.packed_drep[3] = 0x00; /* Reserved for future use. */

   /* Length must be 100, will be set within the encoding function. */
   request.frag_length = 0; 
   request.auth_length = 0;

   request.call_id = ++(epmap->call_id);

   request.alloc_hint = 156; /* This is usually ignored. */
   request.p_cont_id = 0x0000;
   request.opnum = EPT_LOOKUP;

   /* PFC_OBJECT_UUID is not set, there is no optional object UID. */
   /* Stub data, 8-octet aligned. */
   
   ept_lookup.inquiry_type = RPC_C_EP_ALL_ELTS;

   /* Object */
   ept_lookup.object_referent_id = 1;    
   /* UUID filled with garbage. */
   p_uuid = &ept_lookup.object_uuid;
   epmap_string_to_uuid(p_uuid, "cafebabe-cafe-babe-cafe-babecafebabe");
   
   /* Interface */
   ept_lookup.interface_referent_id = 2;
   /* UUID filled with garbage. */
   p_uuid = &ept_lookup.interface_uuid;
   epmap_string_to_uuid(p_uuid, "cafebabe-cafe-babe-cafe-babecafebabe");

   ept_lookup.version_major = 0;
   ept_lookup.version_minor = 0;

   /* Entry handle. */
   ept_lookup.vers_option = 0;

   epmap->handle.attributes = 0;
   ept_lookup.handle = epmap->handle.uuid;
   ept_lookup.max_entries = 1; 
 
   int n = epmap_encode_request(epmap, &request, &ept_lookup);
   if (n == 0) {
     //////  $fixme
   }


   result = epmap_send(epmap);
   if (result != EPMAP_EOK) {
       result |= (WSAGetLastError() << 12);  
       return result;     
   } 

   result = epmap_recv(epmap);
   if (result != EPMAP_EOK) {
       result |= (WSAGetLastError() << 12); 
       return result;
   }

   buffer_seek(epmap, 1, 2, SEEK_SET);
   ptype = ndr_rle8(epmap);
      
   switch(ptype) {
       case RPC_PTYPE_RESPONSE:
           result = epmap_decode_response(epmap, tower, uuid, annot);
           /* $fixme check epmap->status instead. */ 
           /* if result == EPMAP_EOK and epmap->status == ) $fixme */
           if (result == 0x16c9a0d6) {
               epmap_shutdown(epmap); 
               return EPMAP_ENODATA;
           }
           break; 
       case RPC_PTYPE_FAULT:
           result = epmap_decode_fault(epmap);
           result = ((epmap->status) << 12) | EPMAP_EFAULT;  
           break;
       case RPC_PTYPE_CO_CANCEL: /* Not sure we can we receive this. */ 
           result = EPMAP_EPROTO;
           break;   
       default:
           result = EPMAP_EPROTO; /* Malformed PDU or garbage. */ 
           break;

   }

   return result;
}

EPMAPAPI char *epmap_uuid_to_string(const uuid_t *uuid)
{
   static char str[100] = { 0 };

   _snprintf(str, 100, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
       uuid->time_low, uuid->time_mid, uuid->time_hi_and_version,
       uuid->clock_seq_hi_and_reserved, uuid->clock_seq_low,
       uuid->node[0], uuid->node[1], uuid->node[2], 
       uuid->node[3], uuid->node[4], uuid->node[5]); 
   
   return str;   
}

/************************
struct bind_rejection {
   int check;    
   const char *str;
} rejection[7] = { 0 }; 
*****************************/

struct epmap_error {
   uint32_t code;
   const char *str;
} list[] = { 
   { EPMAP_EOK,      "Operation completed successfully" },
   { EPMAP_ENOMEM,   "Insufficient memory to perform the requested operation" },
   { EPMAP_EINVAL,   "An invalid argument was passed to a library function" }, 
   { EPMAP_EBADPTR,  "The system attempted to perform an invalid memory access" }, 
   { EPMAP_EWSAINIT, "The system could not initialize Windows Sockets" },
   { EPMAP_EDNSFAIL, "Could not resolve host name" },
   { EPMAP_ESOCKET,  "Could not connect to the endpoint mapper" },
   { EPMAP_ESEND,    "An error has occurred while sending " },
   { EPMAP_ERECV,    "An error has occurred while receiving " },

   { EPMAP_EACK,     "ACK received. " },
   { EPMAP_ENAK,     "The endpoint mapper did not acknowledge the bind request" }, 
   { EPMAP_EFAULT,   "The endpoint mapped rejected the call request" },
   { EPMAP_EPROTO,   "Protocol error" },
   { 0x402,          "??????????????????????" },

   { EPMAP_ENODATA,  "The endpoint mapped completed. " },
   { 0x407,          "?????????????????????????????????????????????" },
   { 0x408,          "?????????????????????????????????????" },

   { 0xffffffff,      NULL }, 
};

EPMAPAPI char *epmap_error(int result)
{
   static char buffer[256] = { 0 };
   int i, n;
   int offset = 0;
   int status = result & 0xfff;

   for (i = 0; list[i].str != NULL; i++) {
       if (list[i].code ==  status) { /* Mask extended errors, if any. */
           n = i; 
       } 
   }

   offset = _snprintf(buffer, sizeof(buffer), "%s", list[n].str); 

   if (status == EPMAP_ESOCKET) 
       offset = _snprintf(buffer+offset, sizeof(buffer)-offset, " (errno: %u)", result>>12);
   else if (status == EPMAP_ENAK) 
       offset = _snprintf(buffer+offset, sizeof(buffer)-offset, " (reason: %u)", result>>12); 
   else if (status == EPMAP_EFAULT) 
       offset = 0;
  
   return &buffer[0];
}

/* $fixme */
void display_usage(char *progname)
{
    printf("display_usage here!\n");
}


int main(int argc, char *argv[])
{
   epmap_t *epmap = NULL;
   uuid_t uuid;
   uint16_t port; 
   const char *server; 
   char annotation[64+1];
   tower_entry_t tower;
   int count = 0;
   int result = EPMAP_EOK;
   
   if (argc != 2 && argc != 4) {
       fprintf(stderr, "-epmap: Invalid number of arguments.\n");
       display_usage("test");
       return EXIT_FAILURE;
   }
 
   /* Parse arguments here. */
   if (argc == 2) {
       server = argv[1];
       port = DEFAULT_EPMAP_PORT;
   } else { /* argc == 4 */ 

     if (argv[0][1] != 'p' && argv[0][1] !='P') {
         display_usage("Test");
         return EXIT_FAILURE;
      
     }
       server = argv[3];
       port = atoi(argv[2]);
       /* Check port? */
        
   } 

   printf("\nBinding to endpoint portmapper: %s[%u] ...\n", server, port);
   result = epmap_bind(&epmap, server, port);
   if (result != EPMAP_EOK) {
     //////  fprintf(stderr, "-epmap: failed to bind to endpoint portmapper\n"); 
     /////////  fprintf(stderr, "-epmap: An error has occurred: ");

       
       fprintf(stderr, "-epmap: %s.\n", epmap_error(result));   
       return EXIT_FAILURE;
   }

   printf("Querying Endpoint Mapper Database...\n\n");

   /* */
   do {

       memset(&tower, '\0', sizeof(tower_entry_t)); 
       memset(&uuid, '\0', sizeof(uuid_t)); 
       annotation[0] = '\0';
   
       result = epmap_request(epmap, &tower, &uuid, annotation);   
                  
           if (result == EPMAP_EOK) {
               if (tower.tcp_port != 0) {
                   printf("UUID: %s %s\n", epmap_uuid_to_string(&uuid), 
                       strlen(annotation) > 0 ? annotation : ""); 
                   printf("%s:%s[%u]\n\n", 
                       proto_sequence_string(0x07), epmap->server, tower.tcp_port);
                   count++;
               } else if (tower.udp_port != 0) {
                   printf("UUID: %s %s\n", epmap_uuid_to_string(&uuid),
                       strlen(annotation) > 0 ? annotation : "");
                   printf("%s:%s[%u]\n\n",
                       proto_sequence_string(0x08), epmap->server,tower.udp_port);   
                   count++;
               } else {
                   if (tower.named_pipe[0] == '\\' ) { 
                       printf("UUID: %s %s\n", epmap_uuid_to_string(&uuid), annotation);
                       printf("%s:%s[\\%s]\n\n", proto_sequence_string(0x0f), 
                           epmap->server, tower.named_pipe);
                       count++;
               }
           }
                   
       }
 
   } while (result == EPMAP_EOK || result != EPMAP_ENODATA);

   epmap_destroy(epmap);

   if (result != EPMAP_ENODATA) {
       fprintf(stderr, "-epmap: An error has occurred.\n");
       fprintf(stderr, " \n");
       return EXIT_FAILURE;
   }
       
   printf("Total endpoints found: %u \n", count);
   printf("\n======= End of RPC Endpoint Mapper query response =======\n");


   return EXIT_SUCCESS;
}

/******** EOF ********/