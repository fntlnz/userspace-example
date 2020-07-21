#ifndef USERSPACE_COMPAT_H
#define USERSPACE_COMPAT_H
#ifdef __cplusplus
extern "C" {
#endif
int userspace_init();
int example_event(uint64_t timestamp);
#ifdef __cplusplus
}
#endif
#endif // USERSPACE_COMPAT_H
