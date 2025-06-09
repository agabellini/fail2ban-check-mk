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

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph
from cmk.graphing.v1.metrics import (
    Color,
    Metric,
    StrictPrecision,
    Unit,
    DecimalNotation,
    WarningOf,
    CriticalOf,
)


metric_fail2ban_current_failed = Metric(
    name   = 'current_failed',
    title  = Title('Current failed IPs'),
    unit   = Unit(DecimalNotation(''), StrictPrecision(0)),
    color  = Color.LIGHT_BLUE,
)


metric_fail2ban_current_banned = Metric(
    name   = 'current_banned',
    title  = Title('Current banned IPs'),
    unit   = Unit(DecimalNotation(''), StrictPrecision(0)),
    color  = Color.DARK_BLUE,
)


metric_fail2ban_total_failed = Metric(
    name   = 'total_failed',
    title  = Title('Total failed IPs'),
    unit   = Unit(DecimalNotation(''), StrictPrecision(0)),
    color  = Color.LIGHT_ORANGE,
)


metric_fail2ban_total_banned = Metric(
    name   = 'total_banned',
    title  = Title('Total banned IPs'),
    unit   = Unit(DecimalNotation(''), StrictPrecision(0)),
    color  = Color.DARK_ORANGE,
)


graph_fail2ban_current = Graph(
    name   = "current",
    title  = Title("Current IPs"),
    compound_lines = (
        "current_failed",
    ),
    simple_lines = (
        "current_banned",
        WarningOf('current_banned'),
        CriticalOf('current_banned'),
    )
)


graph_fail2ban_total = Graph(
    name   = "total",
    title  = Title("Total IPs"),
    compound_lines = (
        "total_failed",
    ),
    simple_lines = (
        "total_banned",
        WarningOf('total_banned'),
        CriticalOf('total_banned'),
    )
)
