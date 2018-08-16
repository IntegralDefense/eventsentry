from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Try to identify Ursnif by sandbox results.
        for sample in self.event_json['sandbox']:

            """
            OLDER CHECK
            """
            s = 'brdgsjob.exe'

            # Try to identify it by the process tree.
            trees = sample['process_trees'] + sample['process_trees_decoded']
            for tree in trees:
                tree = tree.lower()
                if s.lower() in tree:
                    self.detections.append('Detected Ursnif by the process tree: {}'.format(s))
                    self.tags.append('ursnif')

            # Try to identify it by the dropped files.
            for dropped_file in sample['dropped_files']:
                if dropped_file['filename'].lower() == s:
                    self.detections.append('Detected Ursnif by the dropped file: {}'.format(s))
                    self.tags.append('ursnif')

            """
            NEWER CHECK
            """
            ss = ['powershell.exe', 'FromBase64String', 'System.Uri', 'System.Net.NetworkCredential', 'SecurePassword', 'Write-Host', 'forEach', 'iex', 'getfolderpath', 'DownloadFile', 'StartInfo.FileName', 'StartInfo.Arguments', 'StartInfo.CreateNoWindow', 'System.Diagnostics.ProcessWindowStyle']
            for tree in trees:
                tree = tree.lower()
                if all(s.lower() in tree for s in ss):
                    self.detections.append('Detected Ursnif by all the keywords in the process tree: {}'.format(sorted(ss)))
                    self.tags.append('ursnif')

