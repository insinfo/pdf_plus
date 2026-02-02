part of '../asn1.dart';

///
/// An enum is encoded as an Integer.
///
class ASN1Enumerated extends ASN1Integer {
  ASN1Enumerated(int i, {int tag = ENUMERATED_TYPE})
      : super(BigInt.from(i), tag: tag);
}
