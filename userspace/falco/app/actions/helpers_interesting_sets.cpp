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

#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

void falco::app::actions::configure_interesting_sets(falco::app::state& s)
{
	/* Please note: here we fill these 2 sets because we are interested in only some features, if we leave
	 * them empty `libsinsp` will fill them with all the available syscalls and all the available tracepoints!
	 */

	/* Here the `libsinsp` state set is not enough, we need other syscalls used in the rules,
	 * so we use the `simple_set`, this `simple_set` contains all the syscalls of the `libsinsp` state
	 * plus syscalls for Falco default rules.
	 */
	s.selected_sc_set = libsinsp::events::enforce_simple_sc_set();
	s.selected_event_set = libsinsp::events::sc_set_to_event_set(s.selected_sc_set);

	/* Fill-up the set of event infos of interest */
	for (const auto& ev : libsinsp::events::all_event_set())
	{
		if (!libsinsp::events::is_generic(ev)
			&& !libsinsp::events::is_old_version_event(ev)
			&& !libsinsp::events::is_unused_event(ev)
			&& !libsinsp::events::is_unknown_event(ev))
		{
			/* So far we only covered syscalls, so we add other kinds of
			interesting events. In this case, we are also interested in
			metaevents and in the procexit tracepoint event. */
			if (libsinsp::events::is_metaevent(ev)
				|| ev == ppm_event_code::PPME_PROCEXIT_1_E)
			{
				s.selected_event_set.insert(ev);
			}
		}
	}

	/* In this case we get the tracepoints for the `libsinsp` state and we remove
	 * the `sched_switch` tracepoint since it is highly noisy and not so useful
	 * for our state/events enrichment.
	 */
	s.selected_tp_set = libsinsp::events::sinsp_state_tp_set();
	s.selected_tp_set.remove(ppm_tp_code::SCHED_SWITCH);
}
