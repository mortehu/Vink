#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "wave.h"

static void
wave_init_message(struct wave_message *msg)
{
  ARRAY_INIT(msg);
}

static void
wave_free_message(struct wave_message *msg)
{
  ARRAY_FREE(msg);
}

static int
wave_add_varint(struct wave_message *msg, unsigned int field, uint64_t value)
{
  ARRAY_ADD(msg, (field << 3) | 0);

  do
    {
      if(value > 0x7F)
        ARRAY_ADD(msg, 0x80 | (value & 0x7f));
      else
        ARRAY_ADD(msg, value & 0x7f);

      value >>= 7;
    }
  while(value);

  return ARRAY_RESULT(msg);
}

#if 0
static int
wave_add_varint_signed(struct wave_message *msg, unsigned int field, int64_t value)
{
  uint64_t uvalue;

  if(value >= 0)
    uvalue *= 2;
  else
    uvalue = -value * 2 - 1;

  return wave_add_varint(msg, field, uvalue);
}

static int
wave_add_int64(struct wave_message *msg, unsigned int field, uint64_t value)
{
  ARRAY_ADD(msg, (field << 3) | 1);

  ARRAY_ADD(msg, (value >> 56));
  ARRAY_ADD(msg, (value >> 48));
  ARRAY_ADD(msg, (value >> 40));
  ARRAY_ADD(msg, (value >> 32));
  ARRAY_ADD(msg, (value >> 24));
  ARRAY_ADD(msg, (value >> 16));
  ARRAY_ADD(msg, (value >> 8));
  ARRAY_ADD(msg, (value));

  return ARRAY_RESULT(msg);
}

static int
wave_add_double(struct wave_message *msg, unsigned int field, double value)
{
  wave_add_int64(msg, field, *(uint64_t*) &value);

  return ARRAY_RESULT(msg);
}
#endif

static int
wave_add_bytes(struct wave_message *msg, unsigned int field, const void* string, size_t count)
{
  size_t tmp;

  ARRAY_ADD(msg, (field << 3) | 2);

  tmp = count;

  do
    {
      if(tmp > 0x7F)
        ARRAY_ADD(msg, 0x80 | (tmp & 0x7f));
      else
        ARRAY_ADD(msg, tmp & 0x7f);

      tmp >>= 7;
    }
  while(tmp);

  ARRAY_ADD_SEVERAL(msg, string, count);

  return ARRAY_RESULT(msg);
}

static int
wave_add_message(struct wave_message *target, unsigned int field, const struct wave_message *source)
{
  return wave_add_bytes(target, field, &ARRAY_GET(source, 0), ARRAY_COUNT(source));
}

static void
wave_add_hashed_version(struct wave_message *target, unsigned int field,
                        uint64_t version, const char* hash)
{
  struct wave_message msg;

  wave_init_message(&msg);
  wave_add_varint(&msg, 1, version);
  wave_add_bytes(&msg, 2, hash, strlen(hash));
  wave_add_message(target, field, &msg);
  wave_free_message(&msg);
}

void
wave_wavelet_delta(struct wave_message *target, uint64_t version,
                   const char *hash, const char *author,
                   struct wave_message *operations, size_t operation_count,
                   const char *address_path)
{
  wave_add_hashed_version(target, 1, version, hash);
  wave_add_bytes(target, 2, author, strlen(author));

  while(operation_count--)
    wave_add_message(target, 3, operations++);

  while(*address_path)
    {
      wave_add_bytes(target, 4, address_path, strlen(address_path));
      address_path = strchr(address_path, 0) + 1;
    }
}

void
wave_wavelet_add_participant(struct wave_message *target,
                             const char *address)
{
  wave_add_bytes(target, 1, address, strlen(address));
}

void
wave_wavelet_remove_participant(struct wave_message *target,
                                const char *address)
{
  wave_add_bytes(target, 2, address, strlen(address));
}

#if !1
syntax = "proto2";

package protocol;

option java_package = "org.waveprotocol.wave.protocol";
option java_outer_classname = "common";

/**
 * An immutable list of operations for contribution to a wavelet.
 * Specifies the contributor and the wavelet version that the
 * operations are intended to be applied to.  The host wave server
 * may apply the operations to the wavelet at the specified wavelet version
 * or it may accept them at a later version after operational transformation
 * against the operations at the intermediate wavelet versions.
 */
message ProtocolWaveletDelta {
  // Wavelet version that the delta is intended to be applied to.
  required ProtocolHashedVersion hashedVersion = 1;

  // Wave address of the contributor. Must be an explicit wavelet participant,
  // and may be different from the originator of this delta.
  required string author = 2;

  // Operations included in this delta.
  repeated ProtocolWaveletOperation operation = 3;

  /*
   * The nodes on the "overt" path from the originator through the address
   * access graph leading up to (but excluding) the author. The path excludes
   * any initial segments of the complete path which come before a WRITE edge
   * in the graph. This field is empty if the author is either the originator's
   * entry point into the address graph or is accessed by a WRITE edge.
   *
   * For example, "wave-discuss@acmewave.com" may be the explicit participant of
   * a wavelet, and is set as the author of a delta. However, this group is
   * being asked to act on behalf of "peter@initech-corp.com", who is a member
   * of "wave-authors", which is in turn a member of "wave-discuss". In this
   * example, the delta would be configured as such:
   *  delta.author = "wave-discuss@acmewave.com"
   *  delta.addressPath = ["peter@initech-corp.com", "wave-authors@acmewave.com"]
   */
  repeated string addressPath = 4;
}

/**
 * Describes a wavelet version and the wavelet's history hash at that version.
 */
message ProtocolHashedVersion {
  required int64 version = 1;
  required bytes historyHash = 2;
}

/**
 * An operation within a delta. Exactly one of the following seven fields must be set
 * for this operation to be valid.
 */
message ProtocolWaveletOperation {

  // A document operation. Mutates the contents of the specified document.
  message MutateDocument {
    required string documentId = 1;
    required ProtocolDocumentOperation documentOperation = 2;
  }

  // Adds a new participant (canonicalized wave address) to the wavelet.
  optional string addParticipant = 1;

  // Removes an existing participant (canonicalized wave address) from the wavelet.
  optional string removeParticipant = 2;

  // Mutates a document.
  optional MutateDocument mutateDocument = 3;

  // Does nothing. True if set.
  optional bool noOp = 4;
}

/**
 * A list of mutation components.
 */
message ProtocolDocumentOperation {

  /**
   * A component of a document operation.  One (and only one) of the component
   * types must be set.
   */
  message Component {

    message KeyValuePair {
      required string key = 1;
      required string value = 2;
    }

    message KeyValueUpdate {
      required string key = 1;
      // Absent field means that the attribute was absent/the annotation
      // was null.
      optional string oldValue = 2;
      // Absent field means that the attribute should be removed/the annotation
      // should be set to null.
      optional string newValue = 3;
    }

    message ElementStart {
      required string type = 1;
      // MUST NOT have two pairs with the same key.
      repeated KeyValuePair attribute = 2;
    }

    message ReplaceAttributes {
      // This field is set to true if and only if both oldAttributes and
      // newAttributes are empty.  It is needed to ensure that the optional
      // replaceAttributes component field is not dropped during serialization.
      optional bool empty = 1;
      // MUST NOT have two pairs with the same key.
      repeated KeyValuePair oldAttribute = 2;
      // MUST NOT have two pairs with the same key.
      repeated KeyValuePair newAttribute = 3;
    }

    message UpdateAttributes {
      // This field is set to true if and only if attributeUpdates are empty.
      // It is needed to ensure that the optional updateAttributes
      // component field is not dropped during serialization.
      optional bool empty = 1;
      // MUST NOT have two updates with the same key.
      repeated KeyValueUpdate attributeUpdate = 2;
    }

    message AnnotationBoundary {
      // This field is set to true if and only if both ends and changes are
      // empty.  It is needed to ensure that the optional annotationBoundary
      // component field is not dropped during serialization.
      optional bool empty = 1;
      // MUST NOT have the same string twice.
      repeated string end = 2;
      // MUST NOT have two updates with the same key.  MUST NOT
      // contain any of the strings listed in the 'end' field.
      repeated KeyValueUpdate change = 3;
    }

    optional AnnotationBoundary annotationBoundary = 1;
    optional string characters = 2;
    optional ElementStart elementStart = 3;
    optional bool elementEnd = 4;
    optional int32 retainItemCount = 5;
    optional string deleteCharacters = 6;
    optional ElementStart deleteElementStart = 7;
    optional bool deleteElementEnd = 8;
    optional ReplaceAttributes replaceAttributes = 9;
    optional UpdateAttributes updateAttributes = 10;
  }

  repeated Component component = 1;
}

/**
 * Information generated about this delta post-applicaton. Used in
 * ProtocolUpdate and ProtocolHistoryResponse.
 */
message ProtocolAppliedWaveletDelta {
  required ProtocolSignedDelta signedOriginalDelta = 1;
  optional ProtocolHashedVersion hashedVersionAppliedAt = 2;
  required int32 operationsApplied = 3;
  required int64 applicationTimestamp = 4;
}

/**
 * A delta signed with a number of domain signatures.
 */
message ProtocolSignedDelta {
  required ProtocolWaveletDelta delta = 1;
  repeated ProtocolSignature signature = 2;
}

/**
 * A signature for a delta. It contains the actual bytes of the signature,
 * an identifier of the signer (usually the hash of a certificate chain),
 * and an enum identifying the signature algorithm used.
 */
message ProtocolSignature {

  enum SignatureAlgorithm {
    SHA1_RSA = 1;
  }

  required bytes signatureBytes = 1;
  required bytes signerId = 2;
  required SignatureAlgorithm signatureAlgorithm = 3;
}

/**
 * A certificate chain that a sender will refer to in subsequent signatures.
 *
 * The signer_id field in a ProtocolSignature refers to a ProtocolSignerInfo
 * as follows: The certificates present in a ProtocolSignerInfo are encoded
 * in PkiPath format, and then hashed using the hash algorithm indicated in the
 * ProtocolSignerInfo.
 */
message ProtocolSignerInfo {

  enum HashAlgorithm {
    SHA256 = 1;
    SHA512 = 2;
  }

  // The hash algorithm senders will use to generate an id that will refer to
  // this certificate chain in the future
  required HashAlgorithm hashAlgorithm = 1;

  // The domain that this certificate chain was issued to. Receivers of this
  // ProtocolSignerInfo SHOULD reject the ProtocolSignerInfo if the target
  // certificate (the first one in the list) is not issued to this domain.
  required string domain = 2;

  // The certificate chain. The target certificate (i.e., the certificate issued
  // to the signer) is first, and the CA certificate (or one issued directly
  // by the CA) is last.
  repeated bytes certificate = 3;
}

#endif
