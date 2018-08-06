import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Loda detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each sandboxed sample in the event.
    for sample in event_json['sandbox']:

        # Loop over all of the memory strings.
        for memory_string in sample['memory_strings']:
            
            if '|ddd|' in memory_string and 'beta' in memory_string and '1.0.' in memory_string and memory_string.count('|') == 13:
                detections.append('Detected Loda by the memory string: {}'.format(memory_string))
                tags.append('loda')
                
    return tags, detections, extra
