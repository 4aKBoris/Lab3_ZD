@file:Suppress("unused", "DEPRECATION", "SameParameterValue", "UnnecessaryVariable")

package mpei.lab3

import javafx.application.Platform
import javafx.collections.ObservableList
import javafx.fxml.FXML
import javafx.scene.Scene
import javafx.scene.control.Alert
import javafx.scene.control.ChoiceBox
import javafx.scene.control.TextArea
import javafx.scene.control.TextField
import javafx.scene.layout.VBox
import javafx.stage.FileChooser
import javafx.stage.Modality
import javafx.stage.Stage
import javafx.stage.StageStyle
import tornadofx.View
import tornadofx.asObservable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName


class MainView : View("Лабораторная работа №1") {
    override val root: VBox by fxml()

    private val selectUser: ChoiceBox<String> by fxid("SelectUser")
    private val userName: TextField by fxid("UserName")
    private val watchDocument: TextArea by fxid("WatchDocument")

    init {
        if (!File(pathKeyStore).exists()) {
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(null, keyStorePassword)
            cr.createKeyPair(keyStore, Admin)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
        }

        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        listUsers =
            keyStore.aliases().toList().asObservable()
        selectUser.items = listUsers
        selectUser.selectionModel.selectedItemProperty().addListener { _, _, it -> userName.text = it }
    }

    @FXML
    private fun createFileAction() {
        this.title = "Подписанный документ"
        watchDocument.clear()
    }

    @FXML
    private fun openFileAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Открыть документ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab3_ZD")
            val extFilter = FileChooser.ExtensionFilter("SD files (*.sd)", "*.sd") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage)
            val arr = cr.readFile(file)
            val certSize = arr.cerfSize()
            val signSize = arr.signSize()
            val cSize = arr.copyOfRange(2, 2 + certSize).toString(Charsets.UTF_8).toInt()
            val cerf = arr.copyOfRange(2 + certSize, 2 + certSize + cSize)
            val sign = arr.copyOfRange(2 + certSize + cSize, 2 + certSize + signSize + cSize)
            val crt = File("cert.cer")
            cr.writeFile(crt, cerf)
            val certificateFactory = CertificateFactory.getInstance("X.509")
            val fis = FileInputStream(crt)
            val c = certificateFactory.generateCertificate(fis) as X509Certificate
            fis.close()
            crt.delete()
            this.title = LdapName(c.subjectX500Principal.name).rdns[0].value.toString()
            val text = arr.copyOfRange(2 + cSize + certSize + signSize, arr.size)
            cr.signDec(text, sign, c.publicKey)
            watchDocument.text = text.toString(Charsets.UTF_8)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun saveFileAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Сохранить документ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab3_ZD")
            val extFilter = FileChooser.ExtensionFilter("SD files (*.sd)", "*.sd")
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showSaveDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            val mas = watchDocument.text.toByteArray(Charsets.UTF_8)
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            cr.writeFile(file, cr.signEnc(mas, name))
            cr.createAlert("Документ ${file.name} успешно сохранён!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun closeAction() {
        Platform.exit()
    }

    @FXML
    private fun aboutAction() {
        val aboutWindow = Scene(About().root)
        val newWindow = Stage()
        newWindow.scene = aboutWindow
        newWindow.initModality(Modality.APPLICATION_MODAL)
        newWindow.initOwner(primaryStage)
        newWindow.initStyle(StageStyle.DECORATED)
        newWindow.title = "О программе"
        newWindow.showAndWait()
    }

    @FXML
    private fun deleteKeyPairAction() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            if (!keyStore.containsAlias(name)) throw MyException("Сертификат пользователя $name в хранилище отсутствуют!")
            keyStore.deleteEntry(name)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            cr.createAlert(
                "Сертификат пользователя $name удалён!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
            listUsers.remove(name)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun createKeyPairAction() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            cr.createKeyPair(keyStore, name)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            listUsers.add(name.toLowerCase())
            cr.createAlert(
                "Сертификат для пользователя $name создан!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }


    companion object {
        private lateinit var listUsers: ObservableList<String>
        private val cr = Crypto()

        private fun ByteArray.cerfSize() = this[0] + 128
        private fun ByteArray.signSize() = this[1] + 128
    }
}
