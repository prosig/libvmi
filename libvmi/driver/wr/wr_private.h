#ifndef WR_PRIVATE_H
#define WR_PRIVATE_H


#define WR_SK_INET_PORT         50000


typedef struct wr_instance {
    uint32_t id;
    char *name;
    int socket_fd;
} wr_instance_t;

static inline wr_instance_t *
wr_get_instance(
        vmi_instance_t vmi)
{
    return ((wr_instance_t *)vmi->driver.driver_data);
}

#endif /* WR_PRIVATE_H */
