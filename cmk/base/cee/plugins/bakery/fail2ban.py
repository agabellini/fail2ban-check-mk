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

from pathlib import Path
from cmk.base.plugins.bakery.bakery_api.v1 import (
    OS,
    Plugin,
    register,
)


def get_fail2ban_plugin_files(conf):
    deployment = conf.get('deployment', None)

    if deployment is None:
        interval = conf.get('interval', 0)

        # Legacy deployment
        if interval and isinstance(interval, (int, float)) and interval > 0:
            deployment = ('cached', interval)
        else:
            deployment = ('sync', None)

    match deployment:
        case ('do_not_deploy', _):
            return
        case ('cached', value):
            interval = int(float(value))
        case ('sync', _):
            interval = 0
        case _:
            raise ValueError(f"Invalid deployment value: {deployment}")

    yield Plugin(
        base_os=OS.LINUX,
        source=Path('fail2ban'),
        target=Path('fail2ban'),
        interval=interval,
    )


register.bakery_plugin(
    name = 'fail2ban',
    files_function = get_fail2ban_plugin_files,
)
