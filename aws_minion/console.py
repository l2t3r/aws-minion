import click
import time

from clickclick import format


STYLES = {
    'RUNNING': {'fg': 'green'},
    'TERMINATED': {'fg': 'red'},
}


TITLES = {
    'application_version': 'Ver.',
    'desired_capacity': 'Desired#',
    'created_time': 'Created',
    'launch_time': 'Launched',
    'health_check_http_path': 'Health Check'
}

MAX_COLUMN_WIDTH = {
}


def print_table(cols, rows):
    colwidths = {}

    for col in cols:
        colwidths[col] = len(TITLES.get(col, col))

    for row in rows:
        for col in cols:
            val = row.get(col)
            colwidths[col] = min(max(colwidths[col], len(format(col, val))), MAX_COLUMN_WIDTH.get(col, 1000))

    for i, col in enumerate(cols):
        click.secho(('{:' + str(colwidths[col]) + '}').format(TITLES.get(col, col.title().replace('_', ' '))),
                    nl=False, fg='black', bg='white')
        if i < len(cols)-1:
            click.secho('│', nl=False, fg='black', bg='white')
    click.echo('')

    for row in rows:
        for col in cols:
            val = row.get(col)
            align = ''
            try:
                style = STYLES.get(val, {})
            except:
                # val might not be hashable
                style = {}
            if val is not None and col.endswith('_time'):
                align = '>'
                diff = time.time() - val
                if diff < 900:
                    style = {'fg': 'green', 'bold': True}
                elif diff < 3600:
                    style = {'fg': 'green'}
            elif isinstance(val, int) or isinstance(val, float):
                align = '>'
            val = format(col, val)

            if len(val) > MAX_COLUMN_WIDTH.get(col, 1000):
                val = val[:MAX_COLUMN_WIDTH.get(col, 1000) - 2] + '..'
            click.secho(('{:' + align + str(colwidths[col]) + '}').format(val), nl=False, **style)
            click.echo(' ', nl=False)
        click.echo('')
