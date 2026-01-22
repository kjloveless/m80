#include <dispatch/dispatch.h>
#include <vmnet/vmnet.h>
#include <xpc/xpc.h>

vmnet_return_t m80_vmnet_start_sync(xpc_object_t interface_desc,
    interface_ref *out_iface,
    xpc_object_t *out_params) {
  __block vmnet_return_t status = VMNET_FAILURE;
  __block xpc_object_t params = NULL;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  interface_ref iface = vmnet_start_interface(
      interface_desc,
      dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
      ^(vmnet_return_t s, xpc_object_t p) {
        status = s;
        if (p) {
          params = xpc_retain(p);
        }
        dispatch_semaphore_signal(sema);
      });

  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

  if (out_iface) {
    *out_iface = iface;
  }
  if (out_params) {
    *out_params = params;
  } else if (params) {
    xpc_release(params);
  }

  return status;
}

typedef void (*m80_vmnet_event_cb_t)(interface_event_t, xpc_object_t, void *);

vmnet_return_t m80_vmnet_set_event_callback(interface_ref iface,
    interface_event_t mask,
    dispatch_queue_t queue,
    m80_vmnet_event_cb_t cb,
    void *ctx) {
  return vmnet_interface_set_event_callback(
      iface,
      mask,
      queue,
      ^(interface_event_t event_mask, xpc_object_t event) {
        if (cb) {
          cb(event_mask, event, ctx);
        }
      });
}

vmnet_return_t m80_vmnet_stop_sync(interface_ref iface) {
  __block vmnet_return_t status = VMNET_FAILURE;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  vmnet_return_t schedule = vmnet_stop_interface(
      iface,
      dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
      ^(vmnet_return_t s) {
        status = s;
        dispatch_semaphore_signal(sema);
      });
  if (schedule != VMNET_SUCCESS) {
    return schedule;
  }
  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
  return status;
}
