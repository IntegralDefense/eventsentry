import hashlib
import logging
import requests

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the image URL detection module.')

    tags = []
    detections = []
    extra = []

    # Get the favicon hashes, if there are any.
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36'}
    image_hashes = {}

    # Download and hash any URL with any of these in them.
    image_extensions = ['.ico', '.jpg', '.gif', '.png']

    # Loop over the unique URLs to download and hash any images.
    for url in set([i['value'] for i in event_json['indicators'] if i['type'] == 'URI - URL']):
        try:
            if any(ext in url for ext in image_extensions) and requests.head(url, headers=headers):
                image = requests.get(url, headers=headers).content
                m = hashlib.md5()
                m.update(image)
                image_hashes[m.hexdigest()] = url
        except:
            pass

    # 163 creds harvester.
    hs = ['a14e5365cc2b27ec57e1ab7866c6a228']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Chinese 163 creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('163_themed')

    # Adobe creds harvester.
    hs = ['2712a3d13c5c4c86da9e796b57d78509', '9bd5270d4e723e7995c9c959c5b87e05', '24f56b9a323c92bf7a5428cbb6765eab', '41c1abfbf787df7c1390dba511c2a4a9', '4c69127bf23c89662eeb1bcc3e53427a', 'b0c837095e949bc4d0b7b510295c9640', '416bf6d2943589fcb7aa0de8849f4e94', '01547db5da340b633932c7cfdda2ebcd', '9a6d195497cc64ab5e112c33f0730298', '4898f2d4486d9450d2dbe2a99f62f1ed', '7c8806554edc6e4cc6f3935e535a8af4', 'b0dc946290a4e0d6cff660502a1e29fc', '9adbce15c28900bb2a6d080dac35c76b', 'd61c88fbc42e584e67a30c5d246020f4']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Adobe creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('adobe_themed')

    # BFA Bank creds harvester.
    hs = ['7ef06222f7d7d6f424af2b1215a86998']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the BFA Bank creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('bfa_bank_themed')

    # Chase Bank creds harvester.
    h = '5744986eb3dc6f2da92157a651889902'
    if h in image_hashes:
        detections.append('Detected the Chase Bank creds harvester by the image: {}'.format(image_hashes[h]))
        tags.append('creds_harvesting')
        tags.append('chase_themed')

    # DHL creds harvester.
    hs = ['9c26f4919a06da407b599a871e63d6ff', 'c202d39ed4525922514ffb2087afa583', '2a128d19f7b99b16228f10294a9e82c0', '20923b73933524784a3b398ee70b3825']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the DHL creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('dhl_themed')

    # Docusign creds harvester.
    hs = ['3e47d71cae18960fcd9772c836da50fd', 'ea41e0591755fed52201fc3f96d6376e', '1059986618539574ca4fa0bcfd699006', '0459ad27f51fb7ca4ba02299f8b261ac', '165ee5641d8721ac5dff7ba55256027f', 'de4a3814bdf9535bbf4735858725a7fa']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Docusign creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('docusign_themed')

    # Dropbox creds harvester.
    hs = ['51e2de798b41db26b6a0ec187959d394', '9391620020d44c78b0dc51abbcd151a0', 'e1fb0f2282b9c6232ade1735c934f85d', '0199b4ffa03cfeae45f21748b55bd62b', '475aec3aca1dc0a084970cd99f437823']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Dropbox creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('dropbox_themed')

    # eBay creds harvester.
    hs = ['989d155fe0261a9d9938549a3c2f8168', '4a7f5f9d03a384e497e71f015c93cd3b']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the eBay creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('ebay_themed')

    # Excel creds harvester.
    hs = ['75099623c84266df9d4613b6caa88969', '432bd428f8335f3b49d58b13e9b4b1fc', '4a1b5020244fe390f2e3acdf1c702510', 'db13bce51b6066f4034831db7bd40cda', 'f62b17a56880e4ecb5e119274a5ef0df', 'f62b17a56880e4ecb5e119274a5ef0df', '89e836223d5686ec9a78e11a0fea4a07']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Excel creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('excel_themed')

    # FileInvite creds harvester.
    hs = ['a46a04f1f4245370a002bae0489bec3d', '7560d789bd9c9c12df41a241448ffac7', 'e84677fe10a318a69b47aa20ab36acc5', 'ec2d5aa8f9974ef9f63d83ce135e07d9', '5598a4a4d8cd65340f17014d739c66de', '2e1703b8b06e99c78783af43972599ed']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the FileInvite creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('fileinvite_themed')

    # Google creds harvester.
    hs = ['a300693728f5caa531a6886d9b8f38c2']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Google creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('google_themed')

    # ING Direct creds harvester.
    hs = ['a2025d9c341a20513167370800eea233']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the ING Direct creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('ing_direct_themed')

    # LinkedIn creds harvester.
    hs = ['3d0e5c05903cec0bc8e3fe0cda552745', '2f59e7d0e9372593256cab69a5be9021', '51d9a4347618132e0601c787e3cd352c', '8365d733383f08343012dd7f35b18e1d']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the LinkedIn creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('linkedin_themed')

    # Mailbox creds harvester.
    hs = ['a17ed0bf5dac5685fa9ee56606c59d60', '1de90116079c8a94a54015c674c23c5e']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Mailbox creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('mailbox_themed')

    # Microsoft (generic) creds harvester.
    hs = ['73816c03e30841e18e1ae1a3157e69a1', 'bacd34ac19b7d708f5071f0c669dd497', '3b91f8ad703764af28a70c081ed6db8f', 'deb9fee33dfcefd47ef7c8386fb579e7']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Microsoft creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('microsoft_themed')

    # O365 creds harvester.
    hs = ['12e3dac858061d088023b2bd48e2fa96', '95e1d221f4f2f485c900d7c69d5f8049', 'dd62a417d7f26327110cfdcbd9c437ae', '2d0d8a4705f8fbb1e637a1cf2ae36598', 'e3fc9ea49517cccf805ad6f8431d3c6d', '563829b27e0cdb44d229985a254c0672', '5ec86907c1ac5ef3e117723998feb8be']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the O365 creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('o365_themed')

    # OneDrive creds harvester.
    hs = ['1195bfe885af7c60b352a3b3bef7e42c', '4729768ce8d7be4e64f4b8d661b4c19d', '4ff4a00712c3c5110885d4205d7e47d8', '5cbd8c21cc6a5fd4d9258772d85e47f1', 'b91f9c00577ad8e52b16404b4bdfdba4', 'f9520ee21a2c1512894588df62a77fab', '89994fbb5de49e8ab1914a6bdded89fa', 'a654376b61288b1bfdc9885b24fc259f', '157497df8c3834f392163252305ebca3', 'e12f88bdbe4a7b6ebb53d1fbac780909']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the OneDrive creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('onedrive_themed')

    # PayPal creds harvester.
    hs = ['f955856d3ff447b9ac3191e37906485f', '7fcb8b2360db3cfe650fc067b386984c']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the PayPal creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('paypal_themed')

    # Pretty Envelope creds harvester.
    h = 'c5d76fe02e00a83f31f7d53f20ed5a90'
    if h in image_hashes:
        detections.append('Detected the Pretty Envelope creds harvester by the image: {}'.format(image_hashes[h]))
        tags.append('creds_harvesting')
        tags.append('pretty_envelope')

    # SharePoint creds harvester.
    hs = ['fe563e248e075f7698d3d9c619bf0d23']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the SharePoint creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('sharepoint_themed')

    # SmartSheet creds harvester.
    hs = ['394d4d0163254b8b4d398b264449e933', 'a1e74b1365360ed95b7ce68c872c22d9']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the SmartSheet creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('smartsheet_themed')

    # Roundcube creds harvester.
    h = 'ef9c0362bf20a086bb7c2e8ea346b9f0'
    if h in image_hashes:
        detections.append('Detected the Roundcube creds harvester by the image: {}'.format(image_hashes[h]))
        tags.append('creds_harvesting')
        tags.append('roundcube_themed')

    # WeTransfer creds harvester.
    h = '692e1c7339c359b6412f059c9c9a0474'
    if h in image_hashes:
        detections.append('Detected the WeTransfer creds harvester by the image: {}'.format(image_hashes[h]))
        tags.append('creds_harvesting')
        tags.append('wetransfer_themed')

    # Yahoo creds harvester.
    hs = ['9796ed786d95606d51be9dab54fb5350']
    for h in hs:
        if h in image_hashes:
            detections.append('Detected the Yahoo creds harvester by the image: {}'.format(image_hashes[h]))
            tags.append('creds_harvesting')
            tags.append('yahoo_themed')

    return tags, detections, extra
