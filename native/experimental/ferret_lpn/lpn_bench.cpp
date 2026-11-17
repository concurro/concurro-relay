// Compare the pinned Ferret LPN task with disjoint-group CPU execution.
#include <emp-ot/ferret/lpn_f2.h>
#include <CommonCrypto/CommonDigest.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <sys/resource.h>

/** Run paired synthetic inputs through the original and candidate LPN tasks. */
int main(int argc, char **argv) {
  if (argc != 6) {
    std::cerr << "usage: lpn_bench N K SEED WORKERS REPEATS\n";
    return 2;
  }
  const int64_t n = std::stoll(argv[1]);
  const int k = std::stoi(argv[2]);
  const uint64_t seed_number = std::stoull(argv[3]);
  const int workers = std::stoi(argv[4]);
  const int repeats = std::stoi(argv[5]);
  const emp::block seed = emp::makeBlock(seed_number, seed_number ^ 0xa5a5a5a5);
  emp::PRG input_prg(&seed);
  std::unique_ptr<emp::block[]> original(new emp::block[n]);
  std::unique_ptr<emp::block[]> reference(new emp::block[n]);
  std::unique_ptr<emp::block[]> candidate(new emp::block[n]);
  std::unique_ptr<emp::block[]> key(new emp::block[k]);
  input_prg.random_block(original.get(), static_cast<int>(n));
  input_prg.random_block(key.get(), k);
  LpnF2<emp::NetIO, 10> lpn(emp::ALICE, n, k, nullptr, 1);
  lpn.seed = seed;
  for (int repeat = 0; repeat < repeats; ++repeat) {
    for (int position = 0; position < 2; ++position) {
      const bool parallel = (position == repeat % 2);
      emp::block *const output = parallel ? candidate.get() : reference.get();
      std::memcpy(output, original.get(), n * sizeof(emp::block));
      const auto wall_start = std::chrono::steady_clock::now();
      const auto cpu_start = std::clock();
      if (parallel) lpn.task_parallel(output, key.get(), workers);
      else lpn.task(output, key.get(), 0, n);
      const double wall_ms = std::chrono::duration<double, std::milli>(
          std::chrono::steady_clock::now() - wall_start).count();
      const double cpu_ms = 1000.0 * (std::clock() - cpu_start) / CLOCKS_PER_SEC;
      unsigned char digest[CC_SHA256_DIGEST_LENGTH];
      CC_SHA256(output, static_cast<CC_LONG>(n * sizeof(emp::block)), digest);
      std::ostringstream hex;
      for (unsigned char byte : digest)
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
      struct rusage usage {};
      getrusage(RUSAGE_SELF, &usage);
      std::cout << "{\"n\":" << n << ",\"k\":" << k
                << ",\"seed\":" << seed_number << ",\"workers\":" << workers
                << ",\"repeat\":" << repeat << ",\"variant\":\""
                << (parallel ? "parallel" : "original") << "\",\"wall_ms\":" << wall_ms
                << ",\"cpu_ms\":" << cpu_ms << ",\"peak_rss_bytes\":" << usage.ru_maxrss
                << ",\"output_sha256\":\"" << hex.str() << "\"}" << std::endl;
    }
    if (std::memcmp(reference.get(), candidate.get(), n * sizeof(emp::block)) != 0) {
      std::cerr << "LPN output mismatch at repeat " << repeat << '\n';
      return 1;
    }
  }
}
