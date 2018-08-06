import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Nanocore detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each sandboxed sample in the event.
    for sample in event_json['sandbox']:

        # Loop over all of the memory strings.
        for memory_string in sample['memory_strings']:

            if 'nanocore' in memory_string.lower():
                detections.append('Detected NanoCore by the memory string: {}'.format(memory_string))
                tags.append('nanocore')

        # Loop over all of the process trees.
        trees = sample['process_trees'] + sample['process_trees_decoded']
        for tree in trees:
            tree = tree.lower()

            processes = ['DHCP Service', 'LAN Monitor', 'WAN Host']
            for process in processes:
                if process.lower() in tree:
                    detections.append('Detected Nanocore by the process tree: {}'.format(process))
                    tags.append('nanocore')

    return tags, detections, extra
