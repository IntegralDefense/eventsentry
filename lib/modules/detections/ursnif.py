import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Ursnif detection module.')

    tags = []
    detections = []
    extra = []

    # Try to identify Ursnif by sandbox results.
    for sample in event_json['sandbox']:

        """
        OLDER CHECK
        """
        s = 'brdgsjob.exe'

        # Try to identify it by the process tree.
        trees = sample['process_trees'] + sample['process_trees_decoded']
        for tree in trees:
            tree = tree.lower()
            if s.lower() in tree:
                detections.append('Detected Ursnif by the process tree: {}'.format(s))
                tags.append('ursnif')

        # Try to identify it by the dropped files.
        for dropped_file in sample['dropped_files']:
            if dropped_file['filename'].lower() == s:
                detections.append('Detected Ursnif by the dropped file: {}'.format(s))
                tags.append('ursnif')

        """
        NEWER CHECK
        """
        ss = ['powershell.exe', 'FromBase64String', 'System.Uri', 'System.Net.NetworkCredential', 'SecurePassword', 'Write-Host', 'forEach', 'iex', 'getfolderpath', 'DownloadFile', 'StartInfo.FileName', 'StartInfo.Arguments', 'StartInfo.CreateNoWindow', 'System.Diagnostics.ProcessWindowStyle']
        for tree in trees:
            tree = tree.lower()
            if all(s.lower() in tree for s in ss):
                detections.append('Detected Ursnif by all the keywords in the process tree: {}'.format(sorted(ss)))
                tags.append('ursnif')

    return tags, detections, extra
