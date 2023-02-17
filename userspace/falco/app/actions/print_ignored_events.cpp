/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "actions.h"
#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

/// TODO: probably in the next future would be more meaningful to print the ignored syscalls rather than
/// the ignored events, or maybe change the name of the events since right now they are almost the same of
/// the syscalls.
falco::app::run_result falco::app::actions::print_ignored_events(falco::app::state& s)
{
	/* If the option is true we print the events ignored with Falco `-A`, otherwise
	 * we return immediately.
	 */
	if(!s.options.print_ignored_events)
	{
		return run_result::ok();
	}

	/* Fill the application syscall and tracepoint sets.
	 * The execution will be interrupted after this call so
	 * we don't care if we populate these sets even if the `-A` flag
	 * is not set.
	 */
	configure_interesting_sets(s);

	/* Search for all the ignored syscalls. */
	auto events = libsinsp::events::all_event_set().filter([](ppm_event_code e) {
		return !libsinsp::events::is_old_version_event(e)
				&& !libsinsp::events::is_unused_event(e)
				&& !libsinsp::events::is_unknown_event(e);
	});

	// todo(jasondellaluce,fededp): fix this into libscap as it does not consider old events
	auto ignored_event_names = libsinsp::events::event_set_to_names(events.diff(s.selected_event_set));
	std::cout << "Ignored Event(s):" << std::endl;
	for(const auto& it : ignored_event_names)
	{
		std::cout << "- " << it.c_str() << std::endl;
	}
	std::cout << std::endl;

	return run_result::exit();
}
