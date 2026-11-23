/// ML-KEM and bundle-trust signatures for PQXDH. Isolate when the runtime
/// has one. The stub target ignores [offload].
library;

export 'pq_pqxdh_kem_stub.dart'
    if (dart.library.isolate) 'pq_pqxdh_kem_isolate.dart'
    show
        pqxdhKemDecapsulate,
        pqxdhKemEncapsulate,
        pqxdhTrustSign,
        pqxdhTrustVerify;
