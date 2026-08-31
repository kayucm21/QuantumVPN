package com.quantumvpn.profiles

import android.util.AtomicFile
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

interface AtomicProfileWriter {
    fun writeAtomic(target: File, bytes: ByteArray)

    fun writeProfile(target: File, bytes: ByteArray)

    fun rollbackProfile(target: File): Boolean
}

class AndroidAtomicProfileWriter : AtomicProfileWriter {
    override fun writeAtomic(target: File, bytes: ByteArray) {
        target.parentFile?.let { parent ->
            if (!parent.exists() && !parent.mkdirs()) {
                throw IOException("Не удалось создать ${parent.path}.")
            }
        }
        val atomicFile = AtomicFile(target)
        var stream: FileOutputStream? = null
        try {
            stream = atomicFile.startWrite()
            stream.write(bytes)
            atomicFile.finishWrite(stream)
        } catch (error: Throwable) {
            stream?.let(atomicFile::failWrite)
            throw error
        }
    }

    override fun writeProfile(target: File, bytes: ByteArray) {
        val stage = stageFile(target)
        deleteAtomicFamily(stage)
        writeAtomic(stage, bytes)

        val backup = backupFile(target)
        if (backup.exists() && !backup.delete()) {
            stage.delete()
            throw IOException("Не удалось заменить backup профиля.")
        }
        if (target.exists() && !target.renameTo(backup)) {
            stage.delete()
            throw IOException("Не удалось создать backup профиля.")
        }
        if (!stage.renameTo(target)) {
            if (target.exists()) target.delete()
            if (backup.exists()) backup.renameTo(target)
            throw IOException("Не удалось завершить атомарную запись профиля.")
        }
        deleteAtomicSidecars(stage)
    }

    override fun rollbackProfile(target: File): Boolean {
        val backup = backupFile(target)
        if (!backup.exists()) return false
        if (target.exists() && !target.delete()) return false
        return backup.renameTo(target)
    }

    companion object {
        fun backupFile(target: File): File = File(target.parentFile, "${target.name}.bak")

        fun stageFile(target: File): File = File(target.parentFile, "${target.name}.atomic")

        fun deleteAtomicFamily(target: File) {
            target.delete()
            deleteAtomicSidecars(target)
        }

        fun deleteAtomicSidecars(target: File) {
            File(target.path + ".new").delete()
            File(target.path + ".bak").delete()
        }
    }
}
