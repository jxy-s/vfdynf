/*
    Copyright (c) Johnny Shaw. All rights reserved.
*/
#ifndef _VFDYNFAPI_H_
#define _VFDYNFAPI_H_

EXTERN_C_START

#ifdef _VFDYNFDLL_
#define VFDYNFAPI
#else
#define VFDYNFAPI __declspec(dllimport)
#endif

#define VFDYNF_FAULT_TYPE_WAIT            0x00000001ul
#define VFDYNF_FAULT_TYPE_HEAP            0x00000002ul
#define VFDYNF_FAULT_TYPE_VMEM            0x00000004ul
#define VFDYNF_FAULT_TYPE_REG             0x00000008ul
#define VFDYNF_FAULT_TYPE_FILE            0x00000010ul
#define VFDYNF_FAULT_TYPE_EVENT           0x00000020ul
#define VFDYNF_FAULT_TYPE_SECTION         0x00000040ul
#define VFDYNF_FAULT_TYPE_OLE             0x00000080ul
#define VFDYNF_FAULT_TYPE_INPAGE          0x00000100ul
#define VFDYNF_FAULT_TYPE_FUZZ_REG        0x00000200ul
#define VFDYNF_FAULT_TYPE_FUZZ_FILE       0x00000400ul
#define VFDYNF_FAULT_TYPE_FUZZ_MMAP       0x00000800ul
#define VFDYNF_FAULT_TYPE_FUZZ_NET        0x00001000ul
#define VFDYNF_FAULT_TYPE_ALL             0x00001FFFul

EXTERN_C_END

/**
 * \brief Runtime suppresses fault injection for the process.
 *
 * \details This routine overrides any enabled fault types defined in the
 * application verifier properties. It does not replace them. Suppressing then
 * restoring at runtime will revert back to what is defined in the application
 * verifier settings. This routine is useful if there is a specific path or
 * point in time that the application does not want faults injected.
 *
 * \param[in] FaultMask Mask of the fault types to suppress.
 */
VFDYNFAPI
VOID
NTAPI
AVrfSuppressFaultInjection(
    _In_ ULONG FaultMask
    );

/**
 * \brief Runtime restores fault injection for the process.
 *
 * \details This routine overrides any enabled fault types defined in the
 * application verifier properties. It does not replace them. Suppressing then
 * restoring at runtime will revert back to what is defined in the application
 * verifier settings. This routine is useful if there is a specific path or
 * point in time that the application does not want faults injected.
 *
 * \param[in] FaultMask Mask of the fault types to restore.
 */
VFDYNFAPI
VOID
NTAPI
AVrfRestoreFaultInjection(
    _In_ ULONG FaultMask
    );

/**
 * \brief Runtime suppresses fault injection for the current thread.
 *
 * \details This routine overrides any enabled fault types defined in the
 * application verifier properties. It does not replace them. Suppressing then
 * restoring at runtime will revert back to what is defined in the application
 * verifier settings. This routine is useful if there is a specific path or
 * point in time that the application does not want faults injected.
 *
 * \param[in] FaultMask Mask of the fault types to suppress.
 *
 * \return TRUE if the changes were successfully applied, FALSE otherwise.
 */
VFDYNFAPI
BOOLEAN
NTAPI
AVrfSuppressCurrentThreadFaultInjection(
    _In_ ULONG FaultMask
    );

/**
 * \brief Runtime restores fault injection for the current thread.
 *
 * \details This routine overrides any enabled fault types defined in the
 * application verifier properties. It does not replace them. Suppressing then
 * restoring at runtime will revert back to what is defined in the application
 * verifier settings. This routine is useful if there is a specific path or
 * point in time that the application does not want faults injected.
 *
 * \param[in] FaultMask Mask of the fault types to restore.
 *
 * \return TRUE if the changes were successfully applied, FALSE otherwise.
 */
VFDYNFAPI
BOOLEAN
NTAPI
AVrfRestoreCurrentThreadFaultInjection(
    _In_ ULONG FaultMask
    );

#endif
