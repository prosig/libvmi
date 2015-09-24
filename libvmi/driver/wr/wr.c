#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "private.h"
#include "driver/driver_wrapper.h"
#include "driver/memory_cache.h"
#include "driver/wr/wr.h"
#include "driver/wr/wr_private.h"


enum request_type {
    SK_TYPE_DISCONNECT,
    SK_TYPE_READ,
    SK_TYPE_WRITE,
    SK_TYPE_IDREQ,
};


struct request {
    uint8_t type;       // 0 quit, 1 read, 2 write, ... rest reserved
    uint64_t address;   // address to read from OR write to
    uint64_t length;    // number of bytes to read OR write
} __attribute__((packed));


status_t
wr_test(
    uint64_t id,
    const char *name)
{
    /* TODO */
    return VMI_SUCCESS;
}

static status_t
init_socket(
    wr_instance_t *wr)
{
    struct sockaddr_in address;
    int socket_fd;
    int ret;

    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        dbprint(VMI_DEBUG_WR, "--wr: socket() failed\n");
        return VMI_FAILURE;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(WR_SK_INET_PORT);
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); //inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if ((ret = connect(socket_fd, (struct sockaddr *)&address, sizeof(address))) != 0) {
        dbprint(VMI_DEBUG_WR, "--wr: connect() failed: ret=%d\n", ret);
        perror("connect failed. Error");
        return VMI_FAILURE;
    }

    wr->socket_fd = socket_fd;
    return VMI_SUCCESS;
}

static void
destroy_socket(
    wr_instance_t *wr)
{
    if (wr->socket_fd) {
        struct request req;

        req.type = 0;   // quit
        req.address = 0;
        req.length = 0;

        write(wr->socket_fd, &req, sizeof(struct request));
    }
}

void *
wr_get_memory(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t length)
{
    // allocate one byte more than requested: we adopt the functionality of kvm
    // by letting the wr set the last byte of the buf to a value not equal to 0
    // if everything is fine.
    char *buf = safe_malloc(length + 1);
    struct request req;
    int nbytes = 0;
    wr_instance_t *wr = wr_get_instance(vmi);

    /**
     * TODO: must be implemented to acquire memory from guest
     */

    req.type = SK_TYPE_READ;
    req.address = (uint64_t) paddr;
    req.length = (uint64_t) length + 1;

    // request data
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - requesting data.\n");
    nbytes = write(wr->socket_fd, &req, sizeof(struct request));
    if (nbytes != sizeof(struct request)) {
        goto error_exit;
    }

    // get the requested data from the wr
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - reading data (size=%d).\n", (length+1));
    nbytes = read(wr->socket_fd, buf, length + 1);
    dbprint(VMI_DEBUG_WR, "--wr: get_memory - read %d bytes.\n", nbytes);
    if (nbytes != (length + 1)) {
        goto error_exit;
    }

    // the last byte represents the status of the operation - if the last byte
    // in the buffer is set, everything is fine.
    if (buf[length]) {
        return buf;
    }

error_exit:
    if (buf) {
        free(buf);
    }

    return NULL;
}

void
wr_release_memory(
    void *memory,
    size_t length)
{
    if (memory) {
        free(memory);
    }
}

status_t
wr_setup_live_mode(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);
    dbprint(VMI_DEBUG_WR, "--wr: setup live mode\n");

    memory_cache_destroy(vmi);
    memory_cache_init(vmi, wr_get_memory, wr_release_memory, 0);

    return init_socket(wr);
}

//----------------------------------------------------------------------------
// General Interface Functions (1-1 mapping to driver_* function)

status_t
wr_init(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = g_malloc0(sizeof(wr_instance_t));

    vmi->driver.driver_data = (void *)wr;

    return VMI_SUCCESS;
}

status_t
wr_init_vmi(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);

    wr->socket_fd = 0;

    /**
     * TODO: request nr of vcpu's from WR
     */
    vmi->num_vcpus = 1;

    return wr_setup_live_mode(vmi);
}

void
wr_destroy(
    vmi_instance_t vmi)
{
    wr_instance_t *wr = wr_get_instance(vmi);

    destroy_socket(wr);
    free(wr);
}

uint64_t
wr_get_id(
    vmi_instance_t vmi)
{
    return wr_get_instance(vmi)->id;
}

void
wr_set_id(
    vmi_instance_t vmi,
    uint64_t domainid)
{
    wr_get_instance(vmi)->id = domainid;
}

status_t
wr_get_name(
    vmi_instance_t vmi,
    char **name)
{
    int nbytes;
    struct request req;
    char *tmpname = NULL;
    wr_instance_t *wr = wr_get_instance(vmi);

    tmpname = malloc(42);
    if (tmpname == NULL) {
        return VMI_FAILURE;
    }

    req.type = SK_TYPE_IDREQ;
    req.address = 0;
    req.length = 0;

    nbytes = write(wr->socket_fd, &req, sizeof(struct request));
    if (nbytes <= 0) {
        goto error_exit;
    }

    nbytes = read(wr->socket_fd, tmpname, 42);
    if (nbytes <= 0) {
        goto error_exit;
    }

    *name = strdup(tmpname);

    if (name != NULL) {
        free(tmpname);
    }

    return VMI_SUCCESS;

error_exit:
    if (name != NULL) {
        free(tmpname);
    }

    return VMI_FAILURE;
}

void
wr_set_name(
    vmi_instance_t vmi,
    const char *name)
{
    wr_get_instance(vmi)->name = strndup(name, 42);
}

status_t
wr_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address)
{
    /**
     * TODO: implementation missing...
     */
    *allocated_ram_size = 0x20000000; // fixed to 512MB for now
    *maximum_physical_address = *allocated_ram_size;
}

void *
wr_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
    addr_t paddr = page << vmi->page_shift;
    return memory_cache_insert(vmi, paddr);
}
