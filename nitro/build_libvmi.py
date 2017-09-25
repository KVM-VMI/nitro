from cffi import FFI
ffibuilder = FFI()

c_def = """
#define VMI_INIT_DOMAINNAME 1 /**< initialize using domain name */

#define VMI_INIT_DOMAINID 2 /**< initialize using domain id */

#define VMI_INIT_EVENTS 4 /**< initialize events */

#define VMI_INIT_SHM 8 /**< initialize SHM mode */

// vmi_instance_t
typedef struct vmi_instance *vmi_instance_t;

// addr_t
typedef uint64_t addr_t;

// vmi_pid_t
typedef int32_t vmi_pid_t;

// status_t
typedef enum status {

    VMI_SUCCESS,  /**< return value indicating success */

    VMI_FAILURE   /**< return value indicating failure */
} status_t;

// vmi_config
typedef enum vmi_config {

    VMI_CONFIG_GLOBAL_FILE_ENTRY, /**< config in file provided */

    VMI_CONFIG_STRING,            /**< config string provided */

    VMI_CONFIG_GHASHTABLE,        /**< config GHashTable provided */
} vmi_config_t;

// vmi_mode
typedef enum vmi_mode {

    VMI_XEN, /**< libvmi is monitoring a Xen VM */

    VMI_KVM, /**< libvmi is monitoring a KVM VM */

    VMI_FILE, /**< libvmi is viewing a file on disk */
} vmi_mode_t;

// vmi_init_error_t
typedef enum vmi_init_error {

    VMI_INIT_ERROR_NONE, /**< No error */

    VMI_INIT_ERROR_DRIVER_NOT_DETECTED, /**< Failed to auto-detect hypervisor */

    VMI_INIT_ERROR_DRIVER, /**< Failed to initialize hypervisor-driver */

    VMI_INIT_ERROR_VM_NOT_FOUND, /**< Failed to find the specified VM */

    VMI_INIT_ERROR_PAGING, /**< Failed to determine or initialize paging functions */

    VMI_INIT_ERROR_OS, /**< Failed to determine or initialize OS functions */

    VMI_INIT_ERROR_EVENTS, /**< Failed to initialize events */

    VMI_INIT_ERROR_SHM, /**< Failed to initialize SHM */

    VMI_INIT_ERROR_NO_CONFIG, /**< No configuration was found for OS initialization */

    VMI_INIT_ERROR_NO_CONFIG_ENTRY, /**< Configuration contained no valid entry for VM */
} vmi_init_error_t;

// os_t
typedef enum os {

    VMI_OS_UNKNOWN,  /**< OS type is unknown */

    VMI_OS_LINUX,    /**< OS type is Linux */

    VMI_OS_WINDOWS   /**< OS type is Windows */
} os_t;

typedef enum translation_mechanism {
    VMI_TM_INVALID,         /**< Invalid translation mechanism */
    VMI_TM_NONE,            /**< No translation is required, address is physical address */
    VMI_TM_PROCESS_DTB,     /**< Translate addr via specified directory table base. */
    VMI_TM_PROCESS_PID,     /**< Translate addr by finding process first to use its DTB. */
    VMI_TM_KERNEL_SYMBOL    /**< Find virtual address of kernel symbol and translate it via kernel DTB. */
} translation_mechanism_t;

// access_context_t
typedef struct {
    translation_mechanism_t translate_mechanism;

    addr_t addr;      /**< specify iff using VMI_TM_NONE, VMI_TM_PROCESS_DTB or VMI_TM_PROCESS_PID */
    const char *ksym; /**< specify iff using VMI_TM_KERNEL_SYMBOL */
    addr_t dtb;       /**< specify iff using VMI_TM_PROCESS_DTB */
    vmi_pid_t pid;    /**< specify iff using VMI_TM_PROCESS_PID */
} access_context_t;

// functions
status_t vmi_init_complete(
    vmi_instance_t *vmi,
    void *domain,
    uint64_t init_flags,
    void *init_data,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error);
    
status_t vmi_destroy(
    vmi_instance_t vmi);
    
status_t vmi_translate_ksym2v(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *vaddr);
    
const char* vmi_translate_v2ksym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t va);
    
status_t vmi_translate_kv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    addr_t *paddr);
    
status_t vmi_read_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t *value);
    
status_t vmi_get_offset(
    vmi_instance_t vmi,
    const char *offset_name,
    addr_t *offset);
    
os_t vmi_get_ostype(
    vmi_instance_t vmi);
    
status_t vmi_read_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *value);
    
status_t vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_read
);

status_t vmi_write_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_written);

char *vmi_read_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid);
    
status_t vmi_read_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value);

void vmi_v2pcache_flush(
    vmi_instance_t vmi,
    addr_t dtb);
    
void vmi_pidcache_flush(
    vmi_instance_t vmi);

void vmi_symcache_flush(
    vmi_instance_t vmi);
    
void vmi_rvacache_flush(
    vmi_instance_t vmi);
"""



ffibuilder.set_source("nitro._libvmi",
    """
    #include <libvmi/libvmi.h>
    """,
    libraries=['vmi'])   # or a list of libraries to link with
    # (more arguments like setup.py's Extension class:
    # include_dirs=[..], extra_objects=[..], and so on)

ffibuilder.cdef(c_def)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)