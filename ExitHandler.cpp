#include "ExitHandler.h"

void ExitHandler::exitHandler( int s ) {
    exitHandler( s, ec_success );
}

void ExitHandler::exitHandler( int s, ExitHandler::exit_code_t ec ) {
    m_signal = s;
    if ( ec != ec_success ) {
        g_ec = ec;
    }
    s_shouldExit = true;
//    // HACK wait for loop in main to send exit call to consensus et al.
//    std::this_thread::sleep_for( std::chrono::milliseconds( 2000 ) );
}

volatile bool ExitHandler::s_shouldExit = false;
volatile int ExitHandler::m_signal = -1;
volatile ExitHandler::exit_code_t ExitHandler::g_ec = ExitHandler::ec_success;
