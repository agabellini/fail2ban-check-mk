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


from cmk.rulesets.v1 import (
    Label,
    Title,
    Help,
)
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    FixedValue,
    DictElement,
    Dictionary,
    TimeSpan,
    TimeMagnitude,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
)
from cmk.rulesets.v1.rule_specs import (
    AgentConfig,
    Topic,
    Help,
)


def migrate_fail2ban_bakery(value):
    #
    # In case of "Do not Deploy", in the configuration file "None" is inserted.
    # In case of synchronous "Deploy", "{}" is inserted.
    # In the call of the migration function, checkmk passes "{}" in both cases,
    # so it is not possible to distinguish the two cases.
    # I choose to migrate to the "Do not Deploy" situation.
    # In this case it will happen that the plugin will not be deployed and you will get an error in the GUI.
    # If I used the opposite logic, the plugin would be deployed everywhere in synchronous mode.
    #

    if isinstance(value, dict) and 'deployment' in value:
        # Already migrated
        return value

    match value:
        case None:
            return {"deployment": ("do_not_deploy", None)}
        case {"interval": interval} if isinstance(interval, (int, float)):
            return {"deployment": ("cached", float(interval))}
        case {"activated": True}:
            return {"deployment": ("sync", None)}
        case {"activated": False}:
            return {"deployment": ("do_not_deploy", None)}
        case {} if not value:
            return {"deployment": ("do_not_deploy", None)}
        case _:
            raise ValueError(f"Unsupported value format: {value}")

    return result


def _parameter_form_fail2ban_bakery():
    return Dictionary(
        migrate = migrate_fail2ban_bakery,
        title   = Title('Fail2Ban (Linux)'),
        elements = {
            'deployment': DictElement(
                parameter_form = CascadingSingleChoice(
                    title = Title('Deployment type'),
                    elements = (
                        CascadingSingleChoiceElement(
                            name = 'sync',
                            title = Title('Deploy the fail2ban plug-in and run it synchronously'),
                            parameter_form = FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name = 'cached',
                            title = Title('Deploy the fail2ban plug-in and run it asynchronously'),
                            parameter_form = TimeSpan(
                                label = Label('Interval for collecting data'),
                                prefill = DefaultValue(300.0),
                                displayed_magnitudes = (
                                    TimeMagnitude.SECOND,
                                    TimeMagnitude.MINUTE,
                                    TimeMagnitude.HOUR,
                                    TimeMagnitude.DAY,
                                )
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name = 'do_not_deploy',
                            title = Title('Do not deploy the fail2ban plug-in'),
                            parameter_form = FixedValue(value=None),
                        ),
                    ),
                    prefill = DefaultValue('cached'),
                ),
            ),
        },
    )


rule_spec_fail2ban_bakery = AgentConfig(
    name           = 'fail2ban',
    title          = Title('Fail2Ban (Linux)'),
    help_text      = Help('This will deploy the agent plugin <tt>fail2ban</tt> to check various jails.'),
    topic          = Topic.CONFIGURATION_DEPLOYMENT,
    parameter_form = _parameter_form_fail2ban_bakery,
)
