'use strict';

// Read raw selections only: recipe/config getters call this helper themselves.
// These are download candidates, not a readiness check. Backend planning still
// validates the tools, architecture, package manager and explicit API flags.
function requiredDownloadActions() {
  const form=document.querySelector('#recipe-form');
  if(!form||typeof state==='undefined'||form.dataset.imageId!==state.selected)return [];
  const node=id=>form.querySelector(`#${id}`),checked=id=>Boolean(node(id)?.checked&&!node(id).disabled),value=id=>node(id)?.value||'';
  const inspection=state.images.find(image=>image.id===state.selected)?.inspection||{},distro=inspection.os?.distro;
  const rpm=['oraclelinux','rhel','centos','rocky','almalinux','fedora'].includes(distro),deb=['ubuntu','debian'].includes(distro);
  const actions=[],packages=value('packages-install').trim().split(/[\s,]+/).filter(Boolean);
  if(packages.length)actions.push({kind:'packages',packages:[...new Set(packages)],unknown:false});
  const removing=value('packages-remove').trim().split(/[\s,]+/).filter(Boolean).length>0;
  const action=(kind,evidence)=>({kind,packages:[],unknown:removing||!evidence||evidence.version!==1||!evidence.tools||(!rpm&&!deb)});
  const need=(result,tools,name,packageName)=>{if(!tools[name]){if(packageName)result.packages.push(packageName);else result.unknown=true;}};
  const finish=result=>{result.packages=[...new Set(result.packages)];if(result.packages.length||result.unknown)actions.push(result);};
  const backend=(tools,kernels,iscsi)=>{
    const entries=Object.values(kernels||{}),archivedDracut=entries.length>0&&entries.every(kernel=>kernel.initramfs_backend==='dracut'||(kernel.portability?.readable===true&&kernel.portability.dracut_modules?.length));
    return tools.dracut&&(rpm||iscsi||archivedDracut)?'dracut':tools['update-initramfs']?'initramfs-tools':tools.dracut?'dracut':null;
  };
  const needListing=(result,tools,selected)=>{
    if(selected)need(result,tools,selected==='dracut'?'lsinitrd':'lsinitramfs',selected==='dracut'?(rpm?'dracut':deb?'dracut-core':null):deb?'initramfs-tools-core':null);
  };
  if(checked('boot-migration-enabled')&&checked('migration-install-packages')&&!inspection.boot?.supported_firmware?.includes('UEFI_64')) {
    const evidence=inspection.uefi_migration,guest=evidence?.guest||{},tools=guest.tools||{},result=action('boot_migration',{...evidence,tools:guest.tools});
    if(rpm)result.packages.push('grub2-efi-x64','grub2-common','grub2-tools'); // RPM migration reinstalls package-owned EFI executables.
    else if(deb&&(!guest.efi_modules||!['grub-install','grub-mkconfig','grub-script-check'].every(name=>tools[name])))result.packages.push('grub-efi-amd64-bin','grub2-common');
    finish(result);
  }
  if(checked('platform-enabled')&&value('platform-strategy')!=='preserve'&&checked('platform-install-packages')) {
    const evidence=inspection.platform,tools=evidence?.tools||{},result=action('platform',evidence),iscsi=value('platform-boot')==='iscsi';
    needListing(result,tools,backend(tools,evidence?.kernels,iscsi));
    if(iscsi){
      const packageName=rpm?'iscsi-initiator-utils':deb?'open-iscsi':null;
      need(result,tools,'iscsiadm',packageName);
      if(evidence?.iscsi_userspace_backend==='iscsiadm'){need(result,tools,'iscsid',packageName);need(result,tools,'iscsi-iname',packageName);}
      else if(evidence?.iscsi_userspace_backend==='iscsistart')need(result,tools,'iscsistart',packageName);
      const modules=evidence?.dracut_modules||[],network=(modules.includes('network-manager')&&tools.NetworkManager)||modules.includes('network')||modules.includes('network-legacy');
      if(!modules.includes('iscsi')||!network)result.packages.push('dracut-network');
    }
    finish(result);
  }
  if(form.querySelector('input[name="target"]:checked')?.value==='oci'&&checked('oci-enabled')&&checked('oci-prepare')&&checked('oci-install-packages')) {
    const evidence=inspection.oci_evidence,tools=evidence?.tools||{},result=action('oci',evidence);
    const defaults=[...form.querySelectorAll('[data-oci-default]')],allowed=[...form.querySelectorAll('[data-oci-allowed]')];
    const decode=text=>{try{return JSON.parse(text);}catch{return null;}};
    const values=key=>{const selected=allowed.filter(input=>input.dataset.ociAllowed===key&&input.checked).map(input=>decode(input.value));return selected.length?selected:[decode(defaults.find(input=>input.dataset.ociDefault===key)?.value)];};
    const iscsi=['Storage.BootVolumeType','Storage.LocalDataVolumeType','Storage.RemoteDataVolumeType'].some(key=>values(key).includes('ISCSI'));
    // Match OCI's kernel archive evidence merge without calling its config getter.
    const kernels=Object.fromEntries(Object.entries(evidence?.kernels||{}).map(([version,kernel])=>{const archived=inspection.platform?.kernels?.[version];return [version,{...kernel,portability:archived?.initrd===kernel.initrd?archived?.portability:{}}];}));
    needListing(result,tools,backend(tools,kernels,values('Storage.BootVolumeType').includes('ISCSI')));
    if(iscsi)need(result,tools,'iscsiadm',rpm?'iscsi-initiator-utils':deb?'open-iscsi':null);
    if(defaults.find(input=>input.dataset.ociDefault==='Storage.Iscsi.MultipathDeviceSupported')?.checked)need(result,tools,'multipath',rpm?'device-mapper-multipath':deb?'multipath-tools':null);
    if(checked('oci-configure-cloud-init'))need(result,tools,'cloud-init',rpm||deb?'cloud-init':null);
    finish(result);
  }
  return actions;
}
function requiredDownloadsEnabled() { return requiredDownloadActions().length>0; }
