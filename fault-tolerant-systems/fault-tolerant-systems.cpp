#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/pattern_formatter.h>
#include"AByz.h"

int main(int argc, char* argv[])
{
	if (argc < 4) {
		std::cout << "Please enter all required command line arguments" << std::endl;
		return 1;
	}

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    console_sink->set_color(spdlog::level::trace, 7);   // White
    console_sink->set_color(spdlog::level::debug, 9);   // Light Blue
    console_sink->set_color(spdlog::level::info, 10);  // Light Green
    console_sink->set_color(spdlog::level::warn, 14);  // Light Yellow
    console_sink->set_color(spdlog::level::err, 12);  // Light Red
    console_sink->set_color(spdlog::level::critical, 79);  // White on Red background (64+15)

    console_sink->set_pattern("%^[%L] [%Y-%m-%d %H:%M:%S.%e] %v%$");

    auto logger = std::make_shared<spdlog::logger>("colored_logger", console_sink);
    spdlog::set_default_logger(logger);
	spdlog::set_level(spdlog::level::debug);

	int N = std::atoi(argv[1]);
	int m = std::atoi(argv[2]);
	bool is_source_faulty = std::atoi(argv[3]) == 1;
	AByz algorithm(N, m, is_source_faulty);
	algorithm.run_algorithm();
	return 0;
}
