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
    Title,
    Help,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostAndItemCondition,
    Topic,
)
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    SimpleLevels,
    LevelDirection,
    Integer,
    String,
    migrate_to_upper_integer_levels,
)


def _parameter_form_fail2ban():
    return Dictionary(
        elements = {
            "failed": DictElement(
                parameter_form = SimpleLevels[int](
                    title                = Title("Number of failed IPs"),
                    form_spec_template   = Integer(),
                    level_direction      = LevelDirection.UPPER,
                    prefill_fixed_levels = DefaultValue(value=(30, 40)),
                    help_text            = Help('This number of IPs have failed multiple times and are banned for a configurable amount of time.'),
                    migrate              = migrate_to_upper_integer_levels,
                ),
            ),
            "banned": DictElement(
                parameter_form = SimpleLevels[int](
                    title                = Title("Number of banned IPs"),
                    form_spec_template   = Integer(),
                    level_direction      = LevelDirection.UPPER,
                    prefill_fixed_levels = DefaultValue(value=(10, 20)),
                    help_text            = Help('This number of IPs have failed multiple times and are banned for a configurable amount of time.'),
                    migrate              = migrate_to_upper_integer_levels,
                ),
            ),
        },
    )


rule_spec_fail2ban = CheckParameters(
    name           = 'fail2ban',
    topic          = Topic.OPERATING_SYSTEM,
    condition      = HostAndItemCondition(
                         item_title = Title('Jail name'),
                         item_form  = String(help_text = Help('Specify the name of the jail (e.g. postfix, recidive) this rule applies to.'))
                     ),
    parameter_form = _parameter_form_fail2ban,
    title          = Title('Number of fail2ban Banned/Failed IPs'),
)
