#ifndef ISAKMP_QKD_H_
#define ISAKMP_QKD_H_

typedef struct isakmp_qkd_t isakmp_qkd_t;

#include <library.h>
#include <qkd/qkd_types.h>
#include <sa/ike_sa.h>
#include <sa/task.h>

/**
 * IKEv1 Quantum Key Distribution task.
 */
struct isakmp_qkd_t {

	/**
	 * Implements task_t interface
	 */
	task_t task;
};

typedef qkd_usage_t isakmp_qkd_usage_e;
typedef qkd_mode_t isakmp_qkd_mode_t;
typedef qkd_params_t isakmp_qkd_params_t;

#define ISAKMP_QKD_REQUIRED QKD_REQUIRED
#define ISAKMP_QKD_PREFERRED QKD_PREFERRED
#define ISAKMP_QKD_MODE_PRF QKD_MODE_PRF
#define ISAKMP_QKD_MODE_XOR QKD_MODE_XOR

/**
 * Create a new IKEv1 Quantum Key Distribution task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE if this task is the initiator, FALSE if responder
 * @return				isakmp_qkd task to handle by the task_manager
 */
isakmp_qkd_t *isakmp_qkd_create(ike_sa_t *ike_sa, bool initiator);

#endif /** ISAKMP_QKD_H_ */
