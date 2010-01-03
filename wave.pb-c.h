/* Generated by the protocol buffer compiler.  DO NOT EDIT! */

#ifndef PROTOBUF_C_wave_2eproto__INCLUDED
#define PROTOBUF_C_wave_2eproto__INCLUDED

#include <google/protobuf-c/protobuf-c.h>

PROTOBUF_C_BEGIN_DECLS


typedef struct _Wave__WaveletDelta Wave__WaveletDelta;
typedef struct _Wave__HashedVersion Wave__HashedVersion;
typedef struct _Wave__WaveletOperation Wave__WaveletOperation;
typedef struct _Wave__WaveletOperation__MutateDocument Wave__WaveletOperation__MutateDocument;
typedef struct _Wave__DocumentOperation Wave__DocumentOperation;
typedef struct _Wave__DocumentOperation__Component Wave__DocumentOperation__Component;
typedef struct _Wave__DocumentOperation__Component__KeyValuePair Wave__DocumentOperation__Component__KeyValuePair;
typedef struct _Wave__DocumentOperation__Component__KeyValueUpdate Wave__DocumentOperation__Component__KeyValueUpdate;
typedef struct _Wave__DocumentOperation__Component__ElementStart Wave__DocumentOperation__Component__ElementStart;
typedef struct _Wave__DocumentOperation__Component__ReplaceAttributes Wave__DocumentOperation__Component__ReplaceAttributes;
typedef struct _Wave__DocumentOperation__Component__UpdateAttributes Wave__DocumentOperation__Component__UpdateAttributes;
typedef struct _Wave__DocumentOperation__Component__AnnotationBoundary Wave__DocumentOperation__Component__AnnotationBoundary;
typedef struct _Wave__AppliedWaveletDelta Wave__AppliedWaveletDelta;
typedef struct _Wave__SignedDelta Wave__SignedDelta;
typedef struct _Wave__Signature Wave__Signature;
typedef struct _Wave__SignerInfo Wave__SignerInfo;


/* --- enums --- */

typedef enum _Wave__Signature__SignatureAlgorithm {
  WAVE__SIGNATURE__SIGNATURE_ALGORITHM__SHA1_RSA = 1
} Wave__Signature__SignatureAlgorithm;
typedef enum _Wave__SignerInfo__HashAlgorithm {
  WAVE__SIGNER_INFO__HASH_ALGORITHM__SHA256 = 1,
  WAVE__SIGNER_INFO__HASH_ALGORITHM__SHA512 = 2
} Wave__SignerInfo__HashAlgorithm;

/* --- messages --- */

struct  _Wave__WaveletDelta
{
  ProtobufCMessage base;
  Wave__HashedVersion *hashedversion;
  char *author;
  size_t n_operation;
  Wave__WaveletOperation **operation;
  size_t n_addresspath;
  char **addresspath;
};
#define WAVE__WAVELET_DELTA__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__wavelet_delta__descriptor) \
    , NULL, NULL, 0,NULL, 0,NULL }


struct  _Wave__HashedVersion
{
  ProtobufCMessage base;
  int64_t version;
  ProtobufCBinaryData historyhash;
};
#define WAVE__HASHED_VERSION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__hashed_version__descriptor) \
    , 0, {0,NULL} }


struct  _Wave__WaveletOperation__MutateDocument
{
  ProtobufCMessage base;
  char *documentid;
  Wave__DocumentOperation *documentoperation;
};
#define WAVE__WAVELET_OPERATION__MUTATE_DOCUMENT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__wavelet_operation__mutate_document__descriptor) \
    , NULL, NULL }


struct  _Wave__WaveletOperation
{
  ProtobufCMessage base;
  char *addparticipant;
  char *removeparticipant;
  Wave__WaveletOperation__MutateDocument *mutatedocument;
  protobuf_c_boolean has_noop;
  protobuf_c_boolean noop;
};
#define WAVE__WAVELET_OPERATION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__wavelet_operation__descriptor) \
    , NULL, NULL, NULL, 0,0 }


struct  _Wave__DocumentOperation__Component__KeyValuePair
{
  ProtobufCMessage base;
  char *key;
  char *value;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__KEY_VALUE_PAIR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__key_value_pair__descriptor) \
    , NULL, NULL }


struct  _Wave__DocumentOperation__Component__KeyValueUpdate
{
  ProtobufCMessage base;
  char *key;
  char *oldvalue;
  char *newvalue;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__KEY_VALUE_UPDATE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__key_value_update__descriptor) \
    , NULL, NULL, NULL }


struct  _Wave__DocumentOperation__Component__ElementStart
{
  ProtobufCMessage base;
  char *type;
  size_t n_attribute;
  Wave__DocumentOperation__Component__KeyValuePair **attribute;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__ELEMENT_START__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__element_start__descriptor) \
    , NULL, 0,NULL }


struct  _Wave__DocumentOperation__Component__ReplaceAttributes
{
  ProtobufCMessage base;
  protobuf_c_boolean has_empty;
  protobuf_c_boolean empty;
  size_t n_oldattribute;
  Wave__DocumentOperation__Component__KeyValuePair **oldattribute;
  size_t n_newattribute;
  Wave__DocumentOperation__Component__KeyValuePair **newattribute;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__REPLACE_ATTRIBUTES__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__replace_attributes__descriptor) \
    , 0,0, 0,NULL, 0,NULL }


struct  _Wave__DocumentOperation__Component__UpdateAttributes
{
  ProtobufCMessage base;
  protobuf_c_boolean has_empty;
  protobuf_c_boolean empty;
  size_t n_attributeupdate;
  Wave__DocumentOperation__Component__KeyValueUpdate **attributeupdate;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__UPDATE_ATTRIBUTES__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__update_attributes__descriptor) \
    , 0,0, 0,NULL }


struct  _Wave__DocumentOperation__Component__AnnotationBoundary
{
  ProtobufCMessage base;
  protobuf_c_boolean has_empty;
  protobuf_c_boolean empty;
  size_t n_end;
  char **end;
  size_t n_change;
  Wave__DocumentOperation__Component__KeyValueUpdate **change;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__ANNOTATION_BOUNDARY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__annotation_boundary__descriptor) \
    , 0,0, 0,NULL, 0,NULL }


struct  _Wave__DocumentOperation__Component
{
  ProtobufCMessage base;
  Wave__DocumentOperation__Component__AnnotationBoundary *annotationboundary;
  char *characters;
  Wave__DocumentOperation__Component__ElementStart *elementstart;
  protobuf_c_boolean has_elementend;
  protobuf_c_boolean elementend;
  protobuf_c_boolean has_retainitemcount;
  int32_t retainitemcount;
  char *deletecharacters;
  Wave__DocumentOperation__Component__ElementStart *deleteelementstart;
  protobuf_c_boolean has_deleteelementend;
  protobuf_c_boolean deleteelementend;
  Wave__DocumentOperation__Component__ReplaceAttributes *replaceattributes;
  Wave__DocumentOperation__Component__UpdateAttributes *updateattributes;
};
#define WAVE__DOCUMENT_OPERATION__COMPONENT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__component__descriptor) \
    , NULL, NULL, NULL, 0,0, 0,0, NULL, NULL, 0,0, NULL, NULL }


struct  _Wave__DocumentOperation
{
  ProtobufCMessage base;
  size_t n_component;
  Wave__DocumentOperation__Component **component;
};
#define WAVE__DOCUMENT_OPERATION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__document_operation__descriptor) \
    , 0,NULL }


struct  _Wave__AppliedWaveletDelta
{
  ProtobufCMessage base;
  Wave__SignedDelta *signedoriginaldelta;
  Wave__HashedVersion *hashedversionappliedat;
  int32_t operationsapplied;
  int64_t applicationtimestamp;
};
#define WAVE__APPLIED_WAVELET_DELTA__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__applied_wavelet_delta__descriptor) \
    , NULL, NULL, 0, 0 }


struct  _Wave__SignedDelta
{
  ProtobufCMessage base;
  Wave__WaveletDelta *delta;
  size_t n_signature;
  Wave__Signature **signature;
};
#define WAVE__SIGNED_DELTA__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__signed_delta__descriptor) \
    , NULL, 0,NULL }


struct  _Wave__Signature
{
  ProtobufCMessage base;
  ProtobufCBinaryData signaturebytes;
  ProtobufCBinaryData signerid;
  Wave__Signature__SignatureAlgorithm signaturealgorithm;
};
#define WAVE__SIGNATURE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__signature__descriptor) \
    , {0,NULL}, {0,NULL}, 0 }


struct  _Wave__SignerInfo
{
  ProtobufCMessage base;
  Wave__SignerInfo__HashAlgorithm hashalgorithm;
  char *domain;
  size_t n_certificate;
  ProtobufCBinaryData *certificate;
};
#define WAVE__SIGNER_INFO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&wave__signer_info__descriptor) \
    , 0, NULL, 0,NULL }


/* Wave__WaveletDelta methods */
void   wave__wavelet_delta__init
                     (Wave__WaveletDelta         *message);
size_t wave__wavelet_delta__get_packed_size
                     (const Wave__WaveletDelta   *message);
size_t wave__wavelet_delta__pack
                     (const Wave__WaveletDelta   *message,
                      uint8_t             *out);
size_t wave__wavelet_delta__pack_to_buffer
                     (const Wave__WaveletDelta   *message,
                      ProtobufCBuffer     *buffer);
Wave__WaveletDelta *
       wave__wavelet_delta__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__wavelet_delta__free_unpacked
                     (Wave__WaveletDelta *message,
                      ProtobufCAllocator *allocator);
/* Wave__HashedVersion methods */
void   wave__hashed_version__init
                     (Wave__HashedVersion         *message);
size_t wave__hashed_version__get_packed_size
                     (const Wave__HashedVersion   *message);
size_t wave__hashed_version__pack
                     (const Wave__HashedVersion   *message,
                      uint8_t             *out);
size_t wave__hashed_version__pack_to_buffer
                     (const Wave__HashedVersion   *message,
                      ProtobufCBuffer     *buffer);
Wave__HashedVersion *
       wave__hashed_version__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__hashed_version__free_unpacked
                     (Wave__HashedVersion *message,
                      ProtobufCAllocator *allocator);
/* Wave__WaveletOperation methods */
void   wave__wavelet_operation__init
                     (Wave__WaveletOperation         *message);
size_t wave__wavelet_operation__get_packed_size
                     (const Wave__WaveletOperation   *message);
size_t wave__wavelet_operation__pack
                     (const Wave__WaveletOperation   *message,
                      uint8_t             *out);
size_t wave__wavelet_operation__pack_to_buffer
                     (const Wave__WaveletOperation   *message,
                      ProtobufCBuffer     *buffer);
Wave__WaveletOperation *
       wave__wavelet_operation__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__wavelet_operation__free_unpacked
                     (Wave__WaveletOperation *message,
                      ProtobufCAllocator *allocator);
/* Wave__DocumentOperation methods */
void   wave__document_operation__init
                     (Wave__DocumentOperation         *message);
size_t wave__document_operation__get_packed_size
                     (const Wave__DocumentOperation   *message);
size_t wave__document_operation__pack
                     (const Wave__DocumentOperation   *message,
                      uint8_t             *out);
size_t wave__document_operation__pack_to_buffer
                     (const Wave__DocumentOperation   *message,
                      ProtobufCBuffer     *buffer);
Wave__DocumentOperation *
       wave__document_operation__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__document_operation__free_unpacked
                     (Wave__DocumentOperation *message,
                      ProtobufCAllocator *allocator);
/* Wave__AppliedWaveletDelta methods */
void   wave__applied_wavelet_delta__init
                     (Wave__AppliedWaveletDelta         *message);
size_t wave__applied_wavelet_delta__get_packed_size
                     (const Wave__AppliedWaveletDelta   *message);
size_t wave__applied_wavelet_delta__pack
                     (const Wave__AppliedWaveletDelta   *message,
                      uint8_t             *out);
size_t wave__applied_wavelet_delta__pack_to_buffer
                     (const Wave__AppliedWaveletDelta   *message,
                      ProtobufCBuffer     *buffer);
Wave__AppliedWaveletDelta *
       wave__applied_wavelet_delta__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__applied_wavelet_delta__free_unpacked
                     (Wave__AppliedWaveletDelta *message,
                      ProtobufCAllocator *allocator);
/* Wave__SignedDelta methods */
void   wave__signed_delta__init
                     (Wave__SignedDelta         *message);
size_t wave__signed_delta__get_packed_size
                     (const Wave__SignedDelta   *message);
size_t wave__signed_delta__pack
                     (const Wave__SignedDelta   *message,
                      uint8_t             *out);
size_t wave__signed_delta__pack_to_buffer
                     (const Wave__SignedDelta   *message,
                      ProtobufCBuffer     *buffer);
Wave__SignedDelta *
       wave__signed_delta__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__signed_delta__free_unpacked
                     (Wave__SignedDelta *message,
                      ProtobufCAllocator *allocator);
/* Wave__Signature methods */
void   wave__signature__init
                     (Wave__Signature         *message);
size_t wave__signature__get_packed_size
                     (const Wave__Signature   *message);
size_t wave__signature__pack
                     (const Wave__Signature   *message,
                      uint8_t             *out);
size_t wave__signature__pack_to_buffer
                     (const Wave__Signature   *message,
                      ProtobufCBuffer     *buffer);
Wave__Signature *
       wave__signature__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__signature__free_unpacked
                     (Wave__Signature *message,
                      ProtobufCAllocator *allocator);
/* Wave__SignerInfo methods */
void   wave__signer_info__init
                     (Wave__SignerInfo         *message);
size_t wave__signer_info__get_packed_size
                     (const Wave__SignerInfo   *message);
size_t wave__signer_info__pack
                     (const Wave__SignerInfo   *message,
                      uint8_t             *out);
size_t wave__signer_info__pack_to_buffer
                     (const Wave__SignerInfo   *message,
                      ProtobufCBuffer     *buffer);
Wave__SignerInfo *
       wave__signer_info__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   wave__signer_info__free_unpacked
                     (Wave__SignerInfo *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Wave__WaveletDelta_Closure)
                 (const Wave__WaveletDelta *message,
                  void *closure_data);
typedef void (*Wave__HashedVersion_Closure)
                 (const Wave__HashedVersion *message,
                  void *closure_data);
typedef void (*Wave__WaveletOperation__MutateDocument_Closure)
                 (const Wave__WaveletOperation__MutateDocument *message,
                  void *closure_data);
typedef void (*Wave__WaveletOperation_Closure)
                 (const Wave__WaveletOperation *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__KeyValuePair_Closure)
                 (const Wave__DocumentOperation__Component__KeyValuePair *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__KeyValueUpdate_Closure)
                 (const Wave__DocumentOperation__Component__KeyValueUpdate *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__ElementStart_Closure)
                 (const Wave__DocumentOperation__Component__ElementStart *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__ReplaceAttributes_Closure)
                 (const Wave__DocumentOperation__Component__ReplaceAttributes *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__UpdateAttributes_Closure)
                 (const Wave__DocumentOperation__Component__UpdateAttributes *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component__AnnotationBoundary_Closure)
                 (const Wave__DocumentOperation__Component__AnnotationBoundary *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation__Component_Closure)
                 (const Wave__DocumentOperation__Component *message,
                  void *closure_data);
typedef void (*Wave__DocumentOperation_Closure)
                 (const Wave__DocumentOperation *message,
                  void *closure_data);
typedef void (*Wave__AppliedWaveletDelta_Closure)
                 (const Wave__AppliedWaveletDelta *message,
                  void *closure_data);
typedef void (*Wave__SignedDelta_Closure)
                 (const Wave__SignedDelta *message,
                  void *closure_data);
typedef void (*Wave__Signature_Closure)
                 (const Wave__Signature *message,
                  void *closure_data);
typedef void (*Wave__SignerInfo_Closure)
                 (const Wave__SignerInfo *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor wave__wavelet_delta__descriptor;
extern const ProtobufCMessageDescriptor wave__hashed_version__descriptor;
extern const ProtobufCMessageDescriptor wave__wavelet_operation__descriptor;
extern const ProtobufCMessageDescriptor wave__wavelet_operation__mutate_document__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__key_value_pair__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__key_value_update__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__element_start__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__replace_attributes__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__update_attributes__descriptor;
extern const ProtobufCMessageDescriptor wave__document_operation__component__annotation_boundary__descriptor;
extern const ProtobufCMessageDescriptor wave__applied_wavelet_delta__descriptor;
extern const ProtobufCMessageDescriptor wave__signed_delta__descriptor;
extern const ProtobufCMessageDescriptor wave__signature__descriptor;
extern const ProtobufCEnumDescriptor    wave__signature__signature_algorithm__descriptor;
extern const ProtobufCMessageDescriptor wave__signer_info__descriptor;
extern const ProtobufCEnumDescriptor    wave__signer_info__hash_algorithm__descriptor;

PROTOBUF_C_END_DECLS


#endif  /* PROTOBUF_wave_2eproto__INCLUDED */
