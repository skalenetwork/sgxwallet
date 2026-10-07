/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <functional>
#include <stdexcept>
#include <unistd.h>

// Header-only so that both testw and the CMake unit tests can use it.
namespace TestSupport {

// Runs _call with a line waiting on stdin; false if _call consumed it.
inline bool leavesStdinUnread(const std::function<void()> &_call) {
  int fds[2];
  if (pipe(fds) != 0 || write(fds[1], "x\n", 2) != 2) {
    throw std::runtime_error("Could not prepare stdin for the test");
  }
  close(fds[1]);
  struct Restore {
    int savedStdin;
    int pipeRead;
    ~Restore() {
      dup2(savedStdin, STDIN_FILENO);
      close(savedStdin);
      close(pipeRead);
    }
  } restore{dup(STDIN_FILENO), fds[0]};
  dup2(fds[0], STDIN_FILENO);

  _call();
  char pending[2];
  return read(STDIN_FILENO, pending, sizeof(pending)) == 2;
}

} // namespace TestSupport
