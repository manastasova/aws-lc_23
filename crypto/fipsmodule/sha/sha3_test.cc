// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <gtest/gtest.h>

#include <sys/ioctl.h>
#include <stdio.h>

#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "internal.h"
#include <openssl/digest.h>

#include "keccak_f1600_tests.h"
#include "keccak_f1600_variants.h"


#define NTEST 1000
static uint32_t NTESTS = 1;

// Add perf linux for benchmarking SHA3/SHAKE
#ifdef __linux__
//#define _GNU_SOURCE //Needed for the perf benchmark measurements
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                       int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
    return ret;
}

#endif

#ifdef __aarch64__
static uint64_t gettime() {
#ifdef __aarch64__
  uint64_t ret = 0;
  //uint64_t hz = 0;
  __asm__ __volatile__ ("isb; mrs %0,cntvct_el0":"=r"(ret));
  //__asm__ __volatile__ ("mrs %0,cntfrq_el0; clz %w0, %w0":"=&r"(hz));
  return ret;
#endif
 
  return 0;
}
#endif
int perf_fd;
static uint64_t start_benchmark(){
    #ifdef __linux__
    NTESTS = NTEST;
    //Setup perf to measure time using the high-resolution task counter
    struct perf_event_attr pe;
    
    
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    perf_fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (perf_fd == -1) {
    fprintf(stderr, "Error opening leader %llx\n", pe.config);
    return -1;
    }
    //fprintf(stderr, "Pre negotiate wire byte counts: IN=[%lu], OUT=[%lu]\n", conn->wire_bytes_in, conn->wire_bytes_out);
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    // Start of section being measured
    return 0;
    #endif
    
    #ifdef __aarch64__
    NTESTS = NTEST;
    return gettime();
    #endif
}

static uint64_t end_benchmark(){
    #ifdef __linux__
    NTESTS = NTEST;
    //// End of section being measured
    uint64_t duration_ns;
     ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
     if (!read(perf_fd, &duration_ns, sizeof(duration_ns))){
       return -1;
     }
     close(perf_fd);
     return (duration_ns);
    #endif

    #ifdef __aarch64__
    NTESTS = NTEST;
    return gettime();
    #endif
}

// SHA3TestVector corresponds to one test case of the NIST published file
// SHA3_256ShortMsg.txt.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
class SHA3TestVector {
 public:
  explicit SHA3TestVector() = default;
  ~SHA3TestVector() = default;

  bool ReadFromFileTest(FileTest *t);

  void NISTTestVectors(const EVP_MD *algorithm) const {
    uint32_t digest_length;
    std::unique_ptr<uint8_t[]> digest(new uint8_t[EVP_MD_size(algorithm)]);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Test the correctness via the Init, Update and Final Digest APIs.
    ASSERT_TRUE(EVP_DigestInit(ctx, algorithm));
    ASSERT_TRUE(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8));
    ASSERT_TRUE(EVP_DigestFinal(ctx, digest.get(), &digest_length));

    ASSERT_EQ(Bytes(digest.get(), EVP_MD_size(algorithm)),
              Bytes(digest_.data(), EVP_MD_size(algorithm)));

    OPENSSL_free(ctx);
  }

  void NISTTestVectors_SingleShot(const EVP_MD *algorithm) const {
    uint32_t digest_length;
    std::unique_ptr<uint8_t[]> digest(new uint8_t[EVP_MD_size(algorithm)]);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Test the correctness via the Single-Shot EVP_Digest APIs.
    ASSERT_TRUE(EVP_Digest(msg_.data(), len_ / 8, digest.get(), &digest_length, algorithm, NULL));

    ASSERT_EQ(Bytes(digest.get(), EVP_MD_size(algorithm)),
              Bytes(digest_.data(), EVP_MD_size(algorithm)));

    OPENSSL_free(ctx);
  }

  void NISTTestVectors_SHAKE128() const {
    uint32_t digest_length = out_len_ / 8;
    std::unique_ptr<uint8_t[]> digest(new uint8_t[digest_length]);

    ASSERT_TRUE(SHAKE128(msg_.data(), msg_.size() , digest.get(), out_len_));

    ASSERT_EQ(Bytes(digest.get(), out_len_ / 8),
            Bytes(digest_.data(), out_len_ / 8));
  }

  void NISTTestVectors_SHAKE256() const {
    uint32_t digest_length = out_len_ / 8;
    std::unique_ptr<uint8_t[]> digest(new uint8_t[digest_length]);

    ASSERT_TRUE(SHAKE256(msg_.data(), msg_.size() , digest.get(), out_len_));

    ASSERT_EQ(Bytes(digest.get(), out_len_ / 8),
            Bytes(digest_.data(), out_len_ / 8));
  }


  void Benchmark_SHAKE128() const {
    uint64_t start_bench = 0, end_bench = 0;
    uint32_t digest_length = out_len_ / 8;
    uint8_t *digest = new uint8_t[digest_length];
   
    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);
    
    start_bench = start_benchmark();
    for (int i = 0; i < (int) NTESTS; i++) {
      ASSERT_TRUE(SHAKE128(msg_.data(), msg_.size() , digest, out_len_));
    }
    end_bench = end_benchmark();

    if (end_bench != 0) {
      printf("SHAKE128 %lu\n", (end_bench - start_bench) / NTESTS);
    }
    else {
      printf("Not supported platform and OS. Could not benchmark SHAKE128\n");
    }

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    delete [] digest;
  }

  void Benchmark_SHAKE256() const {
    uint32_t digest_length = out_len_ / 8;
    uint8_t *digest = new uint8_t[digest_length];

    ASSERT_FALSE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);
    
    ASSERT_TRUE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));
    
    ASSERT_EQ(Bytes(digest, out_len_ / 8),
            Bytes(digest_.data(), out_len_ / 8));

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    ASSERT_FALSE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));

    delete [] digest;
  }



 private:
  uint32_t len_;
  uint32_t out_len_;
  std::vector<uint8_t> msg_;
  std::vector<uint8_t> digest_;
};

// Read the |key| attribute from |file_test| and convert it to an integer.
template <typename T>
bool FileTestReadInt(FileTest *file_test, T *out, const std::string &key) {
  std::string s;
  return file_test->GetAttribute(&s, key) &&
  testing::internal::ParseInt32(testing::Message() << "The value " << s.data() << \
  " is not convertable to an integer.", s.data(), (int *) out);
}

bool SHA3TestVector::ReadFromFileTest(FileTest *t) {
   if (t->HasAttribute("Outputlen")) {
    if (!FileTestReadInt(t, &out_len_, "Outputlen")) {
      return false;
    }
  }

  if (t->HasAttribute("Len")) {
    if (!FileTestReadInt(t, &len_, "Len")) {
      return false;
    }
  }

  if (!t->GetBytes(&msg_, "Msg") ||
      !t->GetBytes(&digest_, "MD")) {
    return false;
  }

  return true;
}

TEST(SHA3Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors(algorithm);
  });
}

TEST(SHA3Test, NISTTestVectors_LongMsg) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors(algorithm);
  });
}

TEST(SHA3Test, NISTTestVectors_SingleShot) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
}

TEST(SHA3Test, NISTTestVectors_SingleShot_LongMsg) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512LongMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
}

TEST(KeccakInternalTest, SqueezeOutputBufferOverflow) {
    EVP_MD_unstable_sha3_enable(true);

    KECCAK1600_CTX ctx;
    std::vector<uint8_t> out;
    std::vector<uint8_t> canary(8);
    std::fill(canary.begin(), canary.end(), 0xff);

    const size_t out_lens[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, (1<<5), (1<<16)+1 };
    for (auto out_len : out_lens) {
        EXPECT_TRUE(SHA3_Init(&ctx, SHA3_PAD_CHAR, SHA3_384_DIGEST_BITLENGTH));
        out.resize(out_len + canary.size());
        std::copy(canary.begin(), canary.end(), out.end() - canary.size());
        SHA3_Squeeze(ctx.A, out.data(), out_len, ctx.block_size);
        EXPECT_TRUE(std::equal(out.end() - canary.size(), out.end(), canary.begin()) == true);
    }

    EVP_MD_unstable_sha3_enable(false);
}

TEST(SHAKE128Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHAKE128VariableOut.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.NISTTestVectors_SHAKE128();
  });
}

TEST(SHAKE256Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHAKE256VariableOut.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.NISTTestVectors_SHAKE256();
  });
}

// Benchmarking functions for SHA3 and SHAKE
TEST(SHA3TestBench, Benchmark_SHA3_224) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors(algorithm);
  });
}
TEST(SHA3TestBench, Benchmark_SHA3_256) {
    FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors(algorithm);
  });
}
TEST(SHA3TestBench, Benchmark_SHA3_384) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors(algorithm);
  });
  }
  TEST(SHA3TestBench, Benchmark_SHA3_512) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors(algorithm);
  });
}

TEST(SHAKE128Test, Benchmark_SHAKE128) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.Benchmark_SHAKE128();
  });
}

TEST(SHAKE128Test, Benchmark_SHAKE256) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3Bench.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.NISTTestVectors_SHAKE128();
  });
}

TEST(KECCAKf1600Test, Hybrid) {
  #ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  EXPECT_TRUE(validate_keccak_f1600_x1_scalar());
  EXPECT_TRUE(validate_keccak_f1600_x2_neon());
  EXPECT_TRUE(validate_keccak_f1600_x2_v84a());
  EXPECT_TRUE(validate_keccak_f1600_x3_neon());
  EXPECT_TRUE(validate_keccak_f1600_x3_v84a());
  EXPECT_TRUE(validate_keccak_f1600_x4_neon());

  EXPECT_TRUE(benchmark_keccak_f1600_x1_scalar());
  EXPECT_TRUE(benchmark_keccak_f1600_x2_neon());
  EXPECT_TRUE(benchmark_keccak_f1600_x2_v84a());
  EXPECT_TRUE(benchmark_keccak_f1600_x3_neon());
  EXPECT_TRUE(benchmark_keccak_f1600_x3_v84a());
  EXPECT_TRUE(benchmark_keccak_f1600_x4_neon());
  #endif
}
