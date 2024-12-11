from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess
import time
from selenium import webdriver

def test_user_registration():
    server = subprocess.Popen(["flask", "run", "--no-debugger", "--port=5000"])
    time.sleep(2)  # Esperar a que el servidor Flask esté listo

    driver = webdriver.Chrome()
    try:
        driver.get("http://127.0.0.1:5000/register")
        assert "Registro" in driver.page_source
    finally:
        driver.quit()
        server.terminate()
        server.wait()

def test_task_creation():
    driver = webdriver.Chrome()

    # Registrar usuario
    driver.get("http://127.0.0.1:5000/register")
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("testpassword")
    driver.find_element(By.TAG_NAME, "button").click()

    # Iniciar sesión
    driver.get("http://127.0.0.1:5000/login")
    driver.find_element(By.NAME, "username").send_keys("testuser")
    driver.find_element(By.NAME, "password").send_keys("testpassword")
    driver.find_element(By.TAG_NAME, "button").click()

    # Agregar tarea
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "descripcion")))
    driver.find_element(By.NAME, "descripcion").send_keys("Nueva tarea")
    driver.find_element(By.ID, "add-task-button").click()

    # Verificar que la tarea fue agregada correctamente
    WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.CLASS_NAME, "card"))
    )
    tasks = driver.find_elements(By.CLASS_NAME, "card")
    assert any(task.find_element(By.NAME, "descripcion").get_attribute("value") == "Nueva tarea" for task in tasks), "La tarea no fue agregada correctamente"

    driver.quit()
