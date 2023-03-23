#include <chrono>
#include <thread>

#include "ExitHandler.h"

void ExitHandler::exitHandler(int s) { exitHandler(s, ec_success); }

void ExitHandler::exitHandler(int s, ExitHandler::exit_code_t ec) {
  m_signal = s;
  if (ec != ec_success) {
    g_ec = ec;
  }
  s_shouldExit = true;
}

volatile bool ExitHandler::s_shouldExit = false;
volatile int ExitHandler::m_signal = -1;
volatile ExitHandler::exit_code_t ExitHandler::g_ec = ExitHandler::ec_success;
