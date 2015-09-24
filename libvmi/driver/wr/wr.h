#ifndef WR_DRIVER_H
#define WR_DRIVER_H

status_t wr_init(
    vmi_instance_t vmi);
status_t wr_init_vmi(
    vmi_instance_t vmi);
void wr_destroy(
    vmi_instance_t vmi);
uint64_t wr_get_id(
    vmi_instance_t vmi);
void wr_set_id(
    vmi_instance_t vmi,
    uint64_t domainid);
status_t wr_get_name(
    vmi_instance_t vmi,
    char **name);
void wr_set_name(
    vmi_instance_t vmi,
    const char *name);
status_t wr_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);
void *wr_read_page(
    vmi_instance_t vmi,
    addr_t page);


static inline status_t
driver_wr_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };

    driver.initialized = true;
    driver.init_ptr = &wr_init;
    driver.init_vmi_ptr = &wr_init_vmi;
    driver.destroy_ptr = &wr_destroy;
    driver.get_id_ptr = &wr_get_id;
    driver.set_id_ptr = &wr_set_id;
    driver.get_name_ptr = &wr_get_name;
    driver.set_name_ptr = &wr_set_name;
    driver.get_memsize_ptr = &wr_get_memsize;
    driver.read_page_ptr = &wr_read_page;

    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif /* WR_DRIVER_H */
