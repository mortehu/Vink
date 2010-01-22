#ifndef VINK_EMAIL_H_
#define VINK_EMAIL_H_ 1

struct vink_email_callbacks
{
  /**
   * Called when a messages is received.
   */
  void (*message)(struct vink_message *message);
};

struct vink_message *
vink_email_parse (const char *data, size_t size);

#endif /* !VINK_EMAIL_H_ */
