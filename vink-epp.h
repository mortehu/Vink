#ifndef VINK_EPP_H_
#define VINK_EPP_H_ 1

#include "tree.h"

struct vink_client;
struct vink_epp_state;

struct vink_epp_callbacks
{
  void (*response)(struct vink_epp_state *state,
                   const char *transaction_id,
                   const struct tree *data);

  /**
   * Called when all requests have been queued in the transport buffer.
   *
   * This is useful for batch mode operation; you may safely end the stream
   * when this function is called.
   */
  void (*queue_empty)(struct vink_epp_state *state);
};

enum vink_epp_transfer_operation
{
  VINK_EPP_REQUEST = 0,
  VINK_EPP_CANCEL = 1,
  VINK_EPP_APPROVE = 2,
  VINK_EPP_REJECT = 3
};

struct vink_epp_state *
vink_epp_state_init (int (*write_func)(const void*, size_t, void*),
                     const char *remote_domain, unsigned int flags,
                     void* arg);

void
vink_epp_set_callbacks (struct vink_epp_state *state,
                        struct vink_epp_callbacks *callbacks);

int
vink_epp_state_data (struct vink_epp_state *state,
                    const void *data, size_t count);

int
vink_epp_state_finished (struct vink_epp_state *state);

void
vink_epp_state_free (struct vink_epp_state *state);

/**
 * Returns ID on succes, -1 on failure.
 *
 * The first ID is guaranteed to be 0.  Subsequent IDs will be equal to the
 * previous plus 1.
 */
int
vink_epp_register_object_type (struct vink_client *client, const char *urn);

/**
 * The EPP <check> command is used to determine if an object can be
 * provisioned within a repository.  It provides a hint that allows a
 * client to anticipate the success or failure of provisioning an object
 * using the <create> command as object provisioning requirements are
 * ultimately a matter of server policy.
 *                                            -- RFC3730 section 2.9.2.1.
 */
int
vink_epp_check (struct vink_client *client, int type,
                const char **objects, size_t count);

/**
 * The EPP <info> command is used to retrieve information associated
 * with an existing object.
 *                                            -- RFC3730 section 2.9.2.2.
 */
int
vink_epp_info (struct vink_client *client);

/**
 * The EPP <poll> command is used to discover and retrieve service
 * messages queued by a server for individual clients.  If the message
 * queue is not empty, a successful response to a <poll> command MUST
 * return the first message from the message queue.
 *                                            -- RFC3730 section 2.9.2.3.
 */
int
vink_epp_poll (struct vink_client *client);

/**
 * The EPP <transfer> command provides a query operation that allows a
 * client to determine real-time status of pending and completed
 * transfer requests.
 *                                            -- RFC3730 section 2.9.2.4.
 */
int
vink_epp_query_transfer (struct vink_client *client);

/**
 * The EPP <create> command is used to create an instance of an object.
 * An object can be created for an indefinite period of time, or an
 * object can be created for a specific validity period.
 *                                            -- RFC3730 section 2.9.3.1.
 */
int
vink_epp_create (struct vink_client *client);

/**
 * The EPP <delete> command is used to remove an instance of an existing
 * object.
 *                                            -- RFC3730 section 2.9.3.2.
 */
int
vink_epp_delete (struct vink_client *client);

/**
 * The EPP <renew> command is used to extend the validity period of an
 * existing object.
 *                                            -- RFC3730 section 2.9.3.3.
 */
int
vink_epp_renew (struct vink_client *client);

/**
 * The EPP <transfer> command is used to manage changes in client
 * sponsorship of an existing object.  Clients can initiate a transfer
 * request, cancel a transfer request, approve a transfer request, and
 * reject a transfer request using the "op" command attribute.
 *                                            -- RFC3730 section 2.9.3.4.
 */
int
vink_epp_transfer (struct vink_client *client,
                  enum vink_epp_transfer_operation op);

/**
 * The EPP <update> command is used to change information associated
 * with an existing object.
 *                                            -- RFC3730 section 2.9.3.5.
 */
int
vink_epp_update (struct vink_client *client);

#endif /* !VINK_EPP_H_ */
