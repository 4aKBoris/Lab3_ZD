@file:Suppress("DEPRECATION")

import mpei.lab3.*
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.x509.X509V3CertificateGenerator
import org.jetbrains.annotations.TestOnly
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import javax.naming.ldap.Rdn
import org.bouncycastle.asn1.x500.style.IETFUtils

import org.bouncycastle.asn1.x500.style.BCStyle
import tornadofx.c
import javax.naming.ldap.LdapName
import org.bouncycastle.asn1.x509.X509Name

import java.util.Vector

import org.bouncycastle.jce.PrincipalUtil

import org.bouncycastle.jce.X509Principal
import org.cryptacular.util.CertUtil
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate


class Test {

    companion object {
        var cr = Crypto()
        @JvmStatic
        fun main(args: Array<String>) {
            Test()
        }
    }

    init {
        testFun()
        //testFun2()
    }

    private fun testFun() {
        val name = "admin"
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate(name)
        val cr = Crypto()
        cr.writeFile(File("cert.cer"), cert.encoded)
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val k = certificateFactory.generateCertificate(FileInputStream(File("cert.cer"))) as X509Certificate
        val principal = k.subjectX500Principal

        val dn: String = k.subjectX500Principal.name
        println(dn)
        val ldapDN = LdapName(dn)
        for (rdn in ldapDN.rdns) {
            println(rdn.type + " -> " + rdn.value)
        }

    }

    @TestOnly
    private fun testFun2() {
        val name = "admin"
        var arr = cr.readFile(File("PK/$name.pub"))
        println(arr.size)
        val a = arr
        val s1 = arr[0].toInt()
        val s2 = arr[1].toInt()
        val login = arr.copyOfRange(2, 2 + s1)
        println(login.toString(Charsets.UTF_8))
        println(arr.size)
        val key = arr.copyOfRange(2 + s1, 2 + s1 + s2)
        println(key.toList())
        println(arr.size)
        println(arr.toList())
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate("$name $SHA1")
        val principal = PrincipalUtil.getSubjectX509Principal(cert as X509Certificate?)
        val values = principal.getValues(X509Name.CN)
        val cn = values[0] as String
        println(cn)

        println(a.copyOf(2 + s1 + s2))
        cr.signDec(a.copyOf(2 + s1 + s2), arr.copyOfRange(2 + s1 + s2, arr.size), cert.publicKey)
    }

    @TestOnly
    private fun testFun3() {
        val name = "losev"
        var arr = cr.readFile(File("losev.txt")).toMutableList()
        val a = arr
        val s1 = arr.removeFirst().toInt()
        val s2 = arr.removeFirst().toInt()
        val login = arr.take(s1)
        println(login.toByteArray().toString(Charsets.UTF_8))
        arr = arr.drop(s1) as MutableList<Byte>
        val sign = arr.take(s2)
        println(sign)
        arr = arr.drop(s2) as MutableList<Byte>
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        val cert = keyStore.getCertificate("$name $SHA384")
        cr.signDec(arr.toByteArray(), sign.toByteArray(), cert.publicKey)
        println(arr.toByteArray().toString(Charsets.UTF_8))
        println(sign)
    }
}