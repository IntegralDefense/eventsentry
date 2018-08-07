import logging
import re

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the jRAT detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each sandboxed sample in the event.
    dropped_path_regex = re.compile(r'\\[a-zA-Z]{11}\\ID\.txt')
    for sample in event_json['sandbox']:
        dropped_name = ''
        dropped_path = ''
        for dropped in sample['dropped_files']:
            if dropped['filename'].startswith('Retrive') and dropped['filename'].endswith('.vbs'):
                dropped_name = dropped['filename']
            if dropped['filename'] == 'ID.txt':
                if dropped_path_regex.search(dropped['path']):
                    dropped_path = dropped['path']
        if dropped_name and dropped_path:
            detections.append('Detected jRAT/Adwind by the dropped file "{}" and dropped path "{}"'.format(dropped_name, dropped_path))
            tags.append('jrat')
            tags.append('adwind')
        elif dropped_name and not dropped_path:
            detections.append('ERROR: Looks like we detected jRAT/Adwind by the dropped file "{}" but did not find ID.txt dropped file path'.format(dropped_name))
        elif dropped_path and not dropped_name:
            detections.append('ERROR: Looks like we detected jRAT/Adwind by the dropped path "{}" but did not find Retrive vbs file'.format(dropped_path))

    return tags, detections, extra
