export function readFile(path: string): string {
    let content = '';
    Java.perform(() => {
        const File = Java.use('java.io.File');
        const FileInputStream = Java.use('java.io.FileInputStream');
        
        const file = File.$new(path);
        const fis = FileInputStream.$new(file);
        const bytes = [];
        
        let byte = fis.read();
        while (byte !== -1) {
            bytes.push(byte);
            byte = fis.read();
        }
        
        fis.close();
        content = String.fromCharCode.apply(null, bytes);
    });
    return content;
}

export function writeFile(path: string, data: string): void {
    Java.perform(() => {
        const File = Java.use('java.io.File');
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        
        const file = File.$new(path);
        const fos = FileOutputStream.$new(file);
        
        for (let i = 0; i < data.length; i++) {
            fos.write(data.charCodeAt(i));
        }
        
        fos.close();
    });
}

export function deleteFile(path: string): boolean {
    let result = false;
    Java.perform(() => {
        const File = Java.use('java.io.File');
        const file = File.$new(path);
        result = file.delete();
    });
    return result;
}

export function fileExists(path: string): boolean {
    let result = false;
    Java.perform(() => {
        const File = Java.use('java.io.File');
        const file = File.$new(path);
        result = file.exists();
    });
    return result;
}