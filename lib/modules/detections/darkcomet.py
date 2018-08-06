import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Dark Comet detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each sandboxed sample in the event.
    for sample in event_json['sandbox']:

        # Loop over all of the mutexes.
        for mutex in sample['mutexes']:
            s = 'DC_MUTEX-'
            if s.lower() in mutex.lower():
                detections.append('Detected Dark Comet by the mutex: {}'.format(mutex))
                tags.append('darkcomet')

    return tags, detections, extra
