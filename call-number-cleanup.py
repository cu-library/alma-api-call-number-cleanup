"""Alma API - Call Number Cleanup"""

import sys
import re
from typing import Callable, Set

import click
import requests
from lxml import etree
from requests.exceptions import RequestException

OFFSET_LIMIT_WINDOW_SIZE = 50


class SetIDNotFoundError(Exception):
    """The set ID for the given set name could not be found."""


def build_can_access_url(api_domain: str, headers: dict) -> Callable[[str], None]:
    """Returns a function which sends the request using the api domain and headers."""

    def can_access_url(url: str):
        params = {'limit': 1}
        r = requests.get(f'https://{api_domain}{url}', params=params, headers=headers)
        r.raise_for_status()

    return can_access_url


def echo_request_exception(e: RequestException):
    print(f'{e.response.url} [{e.response.status_code}]')
    print(e.response.text)


def get_set_id(set_name: str, api_domain: str, headers: dict) -> str:
    """Search the /sets Alma API endpoint for a set with a given name, returning it's ID."""
    for offset in range(0, 1000, OFFSET_LIMIT_WINDOW_SIZE):  # If we need 1000 offsets, we've gone too far
        params = {'limit': OFFSET_LIMIT_WINDOW_SIZE, 'offset': offset}
        r = requests.get(f'https://{api_domain}/almaws/v1/conf/sets', params=params, headers=headers)
        r.raise_for_status()
        json_content = r.json()
        if 'set' not in json_content:
            raise SetIDNotFoundError
        for alma_set in json_content['set']:
            if alma_set['name'] == set_name:
                return alma_set['id']


def get_mms_ids(set_id: str, api_domain: str, headers: dict) -> Set[str]:
    """Returns a set of MMS IDs in a given Alma set."""
    mms_ids = set()
    total_mms_ids = 0
    for offset in range(0, 1000, OFFSET_LIMIT_WINDOW_SIZE):  # If we need 1000 offsets, we've gone too far
        params = {'limit': OFFSET_LIMIT_WINDOW_SIZE, 'offset': offset}
        r = requests.get(f'https://{api_domain}/almaws/v1/conf/sets/{set_id}/members', params=params, headers=headers)
        r.raise_for_status()
        json_content = r.json()
        total_mms_ids = json_content['total_record_count']
        if 'member' not in json_content:
            break
        for record in json_content['member']:
            mms_ids.add(record['id'])
        # The ol' slash-r trick is used here instead of a click progress bar
        # because we don't want to make an initial HTTP request to get the total number of PO Lines in the set.
        click.echo(f'\r{len(mms_ids)}/{total_mms_ids}', nl=False)
        if 'member' not in json_content:
            break
    click.echo('')
    assert len(mms_ids) == total_mms_ids
    return mms_ids


def process_mms_id(mms_id: str, api_domain: str, headers: dict):
    """Clean up the call numbers in a record's holdings."""
    r = requests.get(f'https://{api_domain}/almaws/v1/bibs/{mms_id}/holdings', headers=headers)
    r.raise_for_status()
    content = r.json()
    updated = False
    headers_accept_xml = {'Authorization': headers['Authorization'],
                          'Accept': 'application/xml'}
    for holding in content['holding']:
        holding_updated = process_holdings_record(mms_id, holding['holding_id'], api_domain, headers_accept_xml)
        if holding_updated:
            updated = True

    return updated


def process_holdings_record(mms_id: str, holding_id: str, api_domain: str, headers: dict) -> bool:
    r = requests.get(f'https://{api_domain}/almaws/v1/bibs/{mms_id}/holdings/{holding_id}', headers=headers)
    r.raise_for_status()
    holdings_data = etree.fromstring(r.content)
    updated = False
    for call_number_element in holdings_data.iterfind("record/datafield[@tag='852']"):
        for subfield_h in call_number_element.findall("subfield[@code='h']"):
            updated_subfield_h_text = cleanup_call_number_subfield(subfield_h.text)
            if subfield_h.text != updated_subfield_h_text:
                subfield_h.text = updated_subfield_h_text
                updated = True
        for subfield_i in call_number_element.findall("subfield[@code='i']"):
            updated_subfield_i_text = cleanup_call_number_subfield(subfield_i.text)
            if subfield_i.text != updated_subfield_i_text:
                subfield_i.text = updated_subfield_i_text
                updated = True

    if updated:
        headers_content_type_xml = {'Authorization': headers['Authorization'],
                                    'Content-Type': 'application/xml'}
        r = requests.put(f'https://{api_domain}/almaws/v1/bibs/{mms_id}/holdings/{holding_id}',
                         headers=headers_content_type_xml,
                         data=etree.tostring(holdings_data, encoding='utf-8', xml_declaration=True, standalone=True))
        r.raise_for_status()

    return updated


def cleanup_call_number_subfield(call_number: str) -> str:
    # Add a space between a number then letter pair.
    call_number = re.sub(r'([0-9])([a-zA-Z])', r'\1 \2', call_number)
    # Add a space in front of any period.
    call_number = re.sub(r'([^ ])\.', r'\1 .', call_number)
    # Remove the extra periods from any substring matching space period period...
    call_number = re.sub(r' \.\.+', ' .', call_number)
    # Remove any leading or trailing whitespace
    call_number = call_number.strip()
    return call_number


@click.command()
@click.option('--set-name', help='The name of the set of holdings records we want to update.')
@click.option('--set-id', help='The name of the set of holdings records we want to update.')
@click.option('--api-domain', type=str, default='api-ca.hosted.exlibrisgroup.com')
@click.option('--api-key', type=str, required=True, help='Alma API Key')
def main(set_name, set_id, api_domain, api_key):
    """Call Number Cleanup - Clean up the call number for a set of records in Alma.

    A set name or set ID must be provided.

    The set must be itemized and made public before processing with this tool.
    """
    # Validate input
    if not set_name and not set_id:
        sys.exit('Error: A set name or set ID must be provided.')

    if set_name and set_id:
        sys.exit('Error: A set name OR a set ID can be provided, not both.')

    # Build the headers and the testing function
    headers = {'Authorization': f'apikey {api_key}',
               'Accept': 'application/json'}
    can_access_api = build_can_access_url(api_domain, headers)

    # Ensure we can access the sets API endpoint using the provided key.
    try:
        can_access_api('/almaws/v1/conf/sets')
    except RequestException as e:
        echo_request_exception(e)
        sys.exit('Error: Unable to access /almaws/v1/conf/sets.')

    # If the set name is provided, get the set ID.
    if set_name:
        try:
            set_id = get_set_id(set_name, api_domain, headers)
        except SetIDNotFoundError:
            sys.exit(f'Error: Unable to find set ID for "{set_name}".')
        except RequestException as e:
            echo_request_exception(e)
            sys.exit('Error: Error accessing the Alma API.')
        print(f'Found ID {set_id} for the set "{set_name}".')

    # If the set ID has been provided or found, query the API for the associated pairs of MMS IDs and Holdings IDs.
    try:
        mms_ids = get_mms_ids(set_id, api_domain, headers)
    except RequestException as e:
        echo_request_exception(e)
        sys.exit('Error: Error accessing the Alma API.')

    # Sort and list-ify the set of MMS IDs.
    mms_ids_list = sorted(list(mms_ids))

    # Using the first MMS ID in the list, ensure we can access the bibs API endpoint using the provided key.
    test_bib_url = f'/almaws/v1/bibs/{mms_ids_list[0]}'
    try:
        can_access_api(test_bib_url)
    except RequestException as e:
        echo_request_exception(e)
        sys.exit(f'Error: Unable to access {test_bib_url}.')

    # Track any failed MMS IDs
    failed_mms_ids = []

    # Track updated MMS IDs
    updated_mms_ids = []

    with click.progressbar(mms_ids_list, show_pos=True,
                           label='Cleaning up call numbers', item_show_func=lambda x: x) as progress_for_mms_ids:
        for mms_id in progress_for_mms_ids:
            try:
                updated = process_mms_id(mms_id, api_domain, headers)
                if updated:
                    updated_mms_ids.append(mms_id)
            except RequestException as e:
                failed_mms_ids.append((mms_id, e))

    if updated_mms_ids:
        click.echo('Updated call numbers for MMS IDs:')
        for mms_id in updated_mms_ids:
            click.echo(mms_id)

    # Inform the user about the failed MMS ID updates.
    if failed_mms_ids:
        click.echo(f"{len(failed_mms_ids)} records failed to update:")
        for failed_mms_id, e in failed_mms_ids:
            click.echo(failed_mms_id)
            echo_request_exception(e)

if __name__ == '__main__':
    main()
