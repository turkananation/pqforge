/// ML-KEM-1024 entry used by PQXDH. Isolate when the runtime has one.
library;

export 'pq_pqxdh_kem_stub.dart'
    if (dart.library.isolate) 'pq_pqxdh_kem_isolate.dart'
    show pqxdhKemDecapsulate, pqxdhKemEncapsulate;
