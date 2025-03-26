from flask import Flask, send_from_directory, request, jsonify, send_file
from flask_cors import CORS
import os
import subprocess
import logging
import xml.etree.ElementTree as ET
from werkzeug.utils import secure_filename

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('areversy.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
BUILD_DIR = '/app/frontend/build'
STATIC_DIR = os.path.join(BUILD_DIR, 'static')
UPLOAD_FOLDER = '/app/backend/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ZIPALIGN_FILE = "/app/backend/tools/androidtools/zipalign"
APKSIGNER_FILE = "/app/backend/tools/androidtools/apksigner"
KEYSTORE_FILE = "/app/backend/tools/arevrsy.jks"
ALLOWED_EXTENSIONS = {'apk', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def serve_react():
    logger.debug(f"Serving index.html from {BUILD_DIR}")
    return send_from_directory(BUILD_DIR, 'index.html')

@app.route('/static/js/<path:path>')
def serve_js(path):
    logger.debug(f"Serving JS file: /static/js/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'js'), path)

@app.route('/static/css/<path:path>')
def serve_css(path):
    logger.debug(f"Serving CSS file: /static/css/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'css'), path)

@app.route('/static/media/<path:path>')
def serve_media(path):
    logger.debug(f"Serving media file: /static/media/{path}")
    return send_from_directory(os.path.join(STATIC_DIR, 'media'), path)

@app.route('/<path:path>')
def serve_root_files(path):
    logger.debug(f"Serving root file: /{path}")
    return send_from_directory(BUILD_DIR, path)

@app.route('/uploads/<path:path>')
def serve_uploads(path):
    full_path = os.path.join(UPLOAD_FOLDER, path.lstrip('/'))
    logger.debug(f"Serving uploaded file: /uploads/{path}, resolved to {full_path}")
    if not os.path.exists(full_path):
        logger.error(f"Upload file not found: {full_path}")
        return "File not found", 404
    return send_from_directory(UPLOAD_FOLDER, path.lstrip('/'))

@app.route('/upload', methods=['POST'])
def upload_apk():
    if 'apk' not in request.files:
        logger.error('No APK file provided in request')
        return jsonify({'error': 'No APK file provided'}), 400
    
    apk_file = request.files['apk']
    if not allowed_file(apk_file.filename):
        logger.error(f"Invalid file type for {apk_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    
    apk_filename = secure_filename(apk_file.filename)
    apk_path = os.path.join(UPLOAD_FOLDER, apk_filename)
    logger.info(f"Saving uploaded APK to {apk_path}")
    apk_file.save(apk_path)
    
    decompiled_dir = os.path.join(UPLOAD_FOLDER, 'decompiled_' + apk_filename.rsplit('.', 1)[0])
    logger.info(f"Decompiling APK to {decompiled_dir}")
    try:
        subprocess.run(['java', '-jar', 'tools/apktool.jar', 'd', apk_path, '-o', decompiled_dir, '-f'], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to decompile APK: {e}")
        return jsonify({'error': 'Decompilation failed'}), 500
    
    icons = []
    assets = []
    res_dir = os.path.join(decompiled_dir, 'res')
    logger.debug(f"Scanning {res_dir} for icons and assets")
    for root, _, files in os.walk(res_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if 'mipmap' in root or 'drawable' in root:
                if file.endswith(('.png', '.jpg', '.jpeg')) and 'icon' in file.lower():
                    icons.append(file_path.replace(UPLOAD_FOLDER, ''))
                elif file.endswith(('.png', '.jpg', '.jpeg')):
                    assets.append(file_path.replace(UPLOAD_FOLDER, ''))
    
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    logger.debug(f"Parsing manifest at {manifest_path}")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        permissions = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                      for elem in root.findall('.//uses-permission')]
        listeners = [elem.attrib['{http://schemas.android.com/apk/res/android}name'] 
                    for elem in root.findall('.//receiver') + root.findall('.//service')]
    except ET.ParseError as e:
        logger.error(f"Failed to parse manifest: {e}")
        return jsonify({'error': 'Manifest parsing failed'}), 500
    
    logger.info(f"APK decompiled successfully. Icons: {len(icons)}, Assets: {len(assets)}, Permissions: {len(permissions)}, Listeners: {len(listeners)}")
    return jsonify({
        'message': 'APK decompiled',
        'decompiled_dir': decompiled_dir,
        'icons': icons,
        'assets': assets,
        'permissions': permissions,
        'listeners': listeners
    })

@app.route('/replace_logo', methods=['POST'])
def replace_logo():
    if 'logo' not in request.files or 'decompiled_dir' not in request.form or 'old_logo' not in request.form:
        logger.error('Missing logo, decompiled_dir, or old_logo in request')
        return jsonify({'error': 'Missing logo, decompiled_dir, or old_logo'}), 400
    
    logo_file = request.files['logo']
    decompiled_dir = request.form['decompiled_dir']
    old_logo_path = os.path.join(UPLOAD_FOLDER, request.form['old_logo'].lstrip('/'))
    
    if not allowed_file(logo_file.filename):
        logger.error(f"Invalid logo file type: {logo_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    if not os.path.exists(old_logo_path):
        logger.error(f"Old logo path does not exist: {old_logo_path}")
        return jsonify({'error': 'Old logo not found'}), 400
    
    logger.info(f"Replacing logo at {old_logo_path}")
    logo_file.save(old_logo_path)
    return jsonify({'message': 'Logo replaced successfully'})

@app.route('/replace_asset', methods=['POST'])
def replace_asset():
    if 'asset' not in request.files or 'decompiled_dir' not in request.form or 'old_asset' not in request.form:
        logger.error('Missing asset, decompiled_dir, or old_asset in request')
        return jsonify({'error': 'Missing asset, decompiled_dir, or old_asset'}), 400
    
    asset_file = request.files['asset']
    decompiled_dir = request.form['decompiled_dir']
    old_asset_path = os.path.join(UPLOAD_FOLDER, request.form['old_asset'].lstrip('/'))
    
    if not allowed_file(asset_file.filename):
        logger.error(f"Invalid asset file type: {asset_file.filename}")
        return jsonify({'error': 'Invalid file type'}), 400
    if not os.path.exists(old_asset_path):
        logger.error(f"Old asset path does not exist: {old_asset_path}")
        return jsonify({'error': 'Old asset not found'}), 400
    
    logger.info(f"Replacing asset at {old_asset_path}")
    asset_file.save(old_asset_path)
    return jsonify({'message': 'Asset replaced successfully'})

@app.route('/modify_manifest', methods=['POST'])
def modify_manifest():
    data = request.json
    decompiled_dir = data['decompiled_dir']
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    
    if not os.path.exists(manifest_path):
        logger.error(f"Manifest file not found at {manifest_path}")
        return jsonify({'error': 'Manifest file not found'}), 404
    
    logger.debug(f"Modifying manifest at {manifest_path}")
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}

        current_perms = {elem.attrib[f'{{{ns["android"]}}}name'] for elem in root.findall('.//uses-permission')}
        new_perms = set(data.get('permissions', []))
        logger.debug(f"Current permissions: {current_perms}, New permissions: {new_perms}")
        
        for elem in root.findall('.//uses-permission'):
            perm_name = elem.attrib[f'{{{ns["android"]}}}name']
            if perm_name not in new_perms:
                root.remove(elem)
                logger.info(f"Removed permission: {perm_name}")
        
        for perm in new_perms - current_perms:
            ET.SubElement(root, 'uses-permission', {f'{{{ns["android"]}}}name': perm})
            logger.info(f"Added permission: {perm}")

        for tag in ('receiver', 'service'):
            current_listeners = {elem.attrib[f'{{{ns["android"]}}}name'] for elem in root.findall(f'.//{tag}')}
            new_listeners = set(data.get('listeners', []))
            logger.debug(f"Current {tag}s: {current_listeners}, New {tag}s: {new_listeners}")
            
            for elem in root.findall(f'.//{tag}'):
                name = elem.attrib[f'{{{ns["android"]}}}name']
                if name not in new_listeners:
                    root.remove(elem)
                    logger.info(f"Removed {tag}: {name}")
            for listener in new_listeners - current_listeners:
                ET.SubElement(root, tag, {f'{{{ns["android"]}}}name': listener})
                logger.info(f"Added {tag}: {listener}")

        tree.write(manifest_path, xml_declaration=True, encoding='utf-8')
        logger.info('Manifest updated successfully')
    except Exception as e:
        logger.error(f"Failed to modify manifest: {e}")
        return jsonify({'error': 'Manifest modification failed'}), 500
    
    return jsonify({'message': 'Manifest updated'})

@app.route('/rebuild', methods=['POST'])
def rebuild_apk():
    data = request.json
    decompiled_dir = data['decompiled_dir']
    rebuilt_apk = os.path.join(UPLOAD_FOLDER, 'rebuilt.apk')
    aligned_apk = os.path.join(UPLOAD_FOLDER, 'aligned.apk')
    signed_apk = os.path.join(UPLOAD_FOLDER, 'signed_rebuild.apk')
    
    logger.info(f"Rebuilding APK from {decompiled_dir}")
    
    try:
        subprocess.run(['java', '-jar', 'tools/apktool.jar', 'b', decompiled_dir, '-o', rebuilt_apk], check=True)
        logger.info(f"APK rebuilt to {rebuilt_apk}")

        subprocess.run([ZIPALIGN_FILE, '-v', '4', rebuilt_apk, aligned_apk], check=True)
        logger.info(f"APK zipaligned to {aligned_apk}")

        # Step 3: Sign the APK
        subprocess.run([
            APKSIGNER_FILE, 'sign', 
            '--ks', KEYSTORE_FILE, 
            '--ks-pass', 'pass:areversy',
            '--key-pass', 'pass:areversy', 
            '--out', signed_apk, 
            aligned_apk
        ], check=True)
        logger.info(f"APK signed successfully: {signed_apk}")
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to rebuild, zipalign, or sign APK: {e}")
        return jsonify({'error': 'Rebuild, zipalign, or signing failed'}), 500
    
    return send_file(signed_apk, as_attachment=True, download_name='modified_signed.apk')


if __name__ == '__main__':
    logger.info('Starting AReversy Flask application')
    app.run(host='0.0.0.0', port=5000, debug=True)