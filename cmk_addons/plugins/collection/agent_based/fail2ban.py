#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# (c) Jens Kühnel <fail2ban-checkmk@jens.kuehnel.org> 2021
# (c) Andrea Gabellini <andrea.gabellini@telecomitalia.sm> 2025
#
# Information about fail2ban check_mk module see:
# https://github.com/JensKuehnel/fail2ban-check-mk
#
# Added support for new APIs in version 2.4 (Andrea Gabellini)
#
# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.


# Example for output from agent
# ---------------------------------------------------------
# <<<fail2ban>>>
# Status for the jail: postfix-sasl
# |- Filter
# |  |- Currently failed:	7
# |  |- Total failed:	1839
# |  `- Journal matches:	_SYSTEMD_UNIT=postfix.service
# `- Actions
#    |- Currently banned:	1
#    |- Total banned:	76
# Status for the jail: sshd
# |- Filter
# |  |- Currently failed:	6
# |  |- Total failed:	1066
# |  `- Journal matches:	_SYSTEMD_UNIT=sshd.service + _COMM=sshd
# `- Actions
#    |- Currently banned:	5
#    |- Total banned:	50


from cmk.agent_based.v2 import (
    AgentSection,
    Service,
    check_levels,
    CheckPlugin,
)


def parse_fail2ban(string_table):
    parsed = {}
    currentjail = None

    for line in string_table:
        if len(line) != 2:
            # Not a key-value pair
            continue

        key   = line[0].strip("|-` ")
        value = line[1].strip()

        if key == 'Status for the jail':
            currentjail = value
            parsed[currentjail] = {}
        elif currentjail is not None:
            try:
                parsed[currentjail][key] = int(value)
            except ValueError:
                # we are only interested in the numeric values
                continue

    return parsed


def discover_fail2ban(section):
    for jail in section:
        yield Service(item=jail)


def check_fail2ban(item, params, section):
    try:
        data = section[item]
    except KeyError:
        # removed jails should not create a crash,
        # so we dont yield anything and simply return without anything
        return

    for what in ('failed', 'banned'):
        current_key = f"Currently {what}"
        total_key   = f"Total {what}"

        yield from check_levels(
            data[current_key],
            levels_upper = params.get(what),
            metric_name  = f"current_{what}",
            render_func  = int,
            label        = current_key,
            boundaries   = (0, None),
        )

        yield from check_levels(
            data[total_key],
            metric_name  = f"total_{what}",
            render_func  = int,
            label        = total_key,
            boundaries   = (0, None),
            notice_only  = True,
        )


agent_section_fail2ban = AgentSection(
    name = 'fail2ban',
    parse_function = parse_fail2ban,
)


check_plugin_fail2ban = CheckPlugin(
    name                     = 'fail2ban',
    service_name             = "Jail %s",
    discovery_function       = discover_fail2ban,
    check_function           = check_fail2ban,
    check_ruleset_name       = 'fail2ban',
    check_default_parameters = {
        'banned': ('fixed', (10, 20)),
        'failed': ('fixed', (30, 40)),
    }
)
