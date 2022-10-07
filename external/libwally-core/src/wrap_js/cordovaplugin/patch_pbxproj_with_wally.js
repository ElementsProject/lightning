// from https://github.com/cowbell/cordova-plugin-geofence/blob/20de72b918c779511919f7e38d07721112d4f5c8/hooks/add_swift_support.js

var xcode = require('xcode');
var pbxFile = require('xcode/lib/pbxFile');

var project = xcode.project('platforms/ios/HelloCordova.xcodeproj/project.pbxproj');

function PBXContainerItemProxy(portal, name, guid) {
  var proxyObject = {
    isa: "PBXContainerItemProxy",
    containerPortal: portal,
    proxyType: 2,
    remoteGlobalIDString: guid,
    remoteInfo: '"'+name+'"'
  };
  return proxyObject;
}

function PBXReferenceProxy(remoteRef, name) {
  var proxyObject = {
    isa: "PBXReferenceProxy",
    remoteRef: remoteRef,
    fileType: 'archive.ar',
    path: '"'+name+'"',
    sourceTree: 'BUILT_PRODUCTS_DIR'
  };
  return proxyObject;
}

xcode.project.prototype.addRef = function(src, fpath) {
  var file = new pbxFile(fpath);

  if (this.hasFile(file.path)) return false;

  var fileRefs = this.hash.project.objects['PBXFileReference'];
  var srcRef;
  // console.log(fileRefs)
  for (var k in fileRefs) {
    if (fileRefs[k].name === '"'+src+'"') {
      srcRef = k;
    }
  }
  if (!srcRef) throw new Error("Missing srcRef");

  file.uuid = this.generateUuid();

  var remoteRef = this.generateUuid();
  var containers = this.hash.project.objects['PBXContainerItemProxy'];
  containers[remoteRef] = PBXContainerItemProxy(srcRef, src, this.generateUuid());

  var references = this.hash.project.objects['PBXReferenceProxy'];
  var ref = this.generateUuid()
  references[ref] = PBXReferenceProxy(remoteRef, fpath);

  file.fileRef = ref;

  this.addToPbxBuildFileSection(file);        // PBXBuildFile
  //this.addToPbxFileReferenceSection(file);    // PBXFileReference
  this.addToFrameworksPbxGroup(file);         // PBXGroup

  this.addToPbxFrameworksBuildPhase(file);    // PBXFrameworksBuildPhase

  return file;
}


project.parse(function (err) {
  project.addRef('libwally-core-ios.xcodeproj', 'liblibwally-core-ios.a');
  console.log(project.writeSync());
});
