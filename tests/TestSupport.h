/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <libBLS/backends/algebra.hpp>
#include <condition_variable>
#include <mutex>
#include <random>
#include <string>
#include <vector>

// Generic, workflow-agnostic helpers usable by any test.
namespace TestSupport {

extern std::default_random_engine randGen;

std::string stringFromFr(libBLS::algebra::FrScalar &el,
                         libBLS::algebra::Base base =
                             libBLS::algebra::Base::DEC);

// Convert a decimal string into a zero-padded hex string of numBytes bytes.
std::string convertDecToHex(const std::string &dec, int numBytes = 32);

// Split a delimited string of decimal coefficients into field scalars.
std::vector<libBLS::algebra::FrScalar> splitStringToFr(const char *coeffs,
                                                       char symbol);

// Build a G2 point from a vector of four decimal coordinate strings
// {xC0, xC1, yC0, yC1}.
libBLS::algebra::G2Point
vectStringToG2(const std::vector<std::string> &G2_str_vect);

// Simple start barrier - used by multi-threaded load tests.
struct start_barrier {
  explicit start_barrier(int count) : count(count) {}
  void wait() {
    std::unique_lock<std::mutex> lock(m);
    if (--count == 0) {
      cv.notify_all();
    } else {
      cv.wait(lock, [&] { return count == 0; });
    }
  }

private:
  int count;
  std::mutex m;
  std::condition_variable cv;
};

} // namespace TestSupport
