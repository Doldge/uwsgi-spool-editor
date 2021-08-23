#!usr/bin/env python3

import os
import argparse
import jq
import json
import logging

from typing import Callable, NamedTuple

from uwsgi_spool_editor import Task
logger = logging.getLogger('uwsgi_spooler_modifer.remove')


class SearchValue(NamedTuple):
    key: str
    value: str
    exact: bool = False
    json: bool = False


def scan_content(task: Task, search_value: SearchValue) -> bool:
    """Scans the content dictionary of a task for a key/value match.

    """
    for key, value in task.content_dict.items():
        if key.decode('utf-8') != search_value.key:
            continue
        if not search_value.exact and search_value.value in value.decode('utf-8'):
            print(f'{value.decode("utf-8")} Matches {search_value.value}!')
            return True
        elif search_value.exact and search_value.value == value.decode('utf-8'):
            print(f'{value.decode("utf-8")} Matches {search_value.value}!')
            return True

    return False


def scan_body(task: Task, search_value: SearchValue) -> bool:
    """Scans the body of a task for a key/value match.

    If the body is a JSON serailization, you can use the JQ syntax to search nested keys
    / etc.

    (Only JSON is supported currently.)
    """
    if search_value.json is False:
        raise ValueError('unsure how to parse the Spooler Body')

    if search_value.json is True:
        # Example:
        # .metadata.callback_url
        body = json.loads(task.body.decode('utf-8'))
        value_list = jq.compile(search_value.key).input(body).all()
        logger.debug(value_list)
        for value in value_list:
            if not search_value.exact and search_value.value in value:
                return True
            elif search_value.exact and search_value.value == value:
                return True

    return False


def scan_dir(directory: str, scanner_func: Callable, search_value: SearchValue):
    """Recursively scan the given directory, looking for spool files.

    It also loads each spool file and then calls `scanner_func()` on the spool file to
    determine weather or not to delete the file.

    Arguments:
        directory (str): A Directory to search for uWSGI Spool files.
        scanner_func (callable):    A function that takes a `Task` and a `SearchValue`, and
                                    returns True if the Task should be removed.
        search_value (SearchValue): Object containing the search rules.
    """

    delete_list = []
    for entry in os.scandir(directory):
        if entry.is_dir(follow_symlinks=False):
            scan_dir(entry.path, scanner_func, search_value)

        spooler = Task.load(entry.path)
        should_delete = scanner_func(spooler, search_value)

        if should_delete:
            delete_list.append(entry.path)

    if delete_list:
        print(f'Removing the following Files: {delete_list}')
        for spooler_path in delete_list:
            os.remove(spooler_path)
    else:
        print("No Files found for removal.")


def main() -> bool:
    parser = get_parser()
    cli_args = parser.parse_args()
    cli_args.__dict__['search_value'] = SearchValue(
        key=cli_args.key,
        value=cli_args.value,
        exact=False,
        json=cli_args.json
    )

    if cli_args.verbose:
        logger.setLevel(logging.DEBUG)

    scan_dir(
        cli_args.spooler_dir,
        cli_args.scan_spooler,
        cli_args.search_value
    )
    return False


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scans a directory for spooler files, and deletes all files with"
            " matching key/value pairs."
        )
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Turn on debug output'
    )

    subparsers = parser.add_subparsers()

    content_parser = subparsers.add_parser('content', help='search the content')
    content_parser.add_argument(
        '--key',
        required=True,
        type=str,
        help='key to search for'
    )
    content_parser.add_argument(
        '--value',
        required=True,
        type=str,
        help='value to match the key against'
    )
    content_parser.set_defaults(
        scan_spooler=scan_content
    )

    body_parser = subparsers.add_parser('body', help='search the "body"')
    body_parser.add_argument(
        '--json',
        action='store_true',
        help='decode the body as JSON, before scanning.'
    )
    body_parser.add_argument(
        '--key',
        required=True,
        type=str,
        help=(
            "key to search for. if you're dealing with JSON data use the"
            " jq syntax for searching"
        )
    )
    body_parser.add_argument(
        '--value',
        required=True,
        type=str,
        help='value to match the key against'
    )
    body_parser.set_defaults(
        scan_spooler=scan_body
    )

    parser.add_argument(
        'spooler_dir',
        type=str,
        help='Spooler directory to scan'
    )
    return parser


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.WARNING,
        format='[%(asctime)s] - [%(levelname)s]: %(message)s'
    )
    main()
