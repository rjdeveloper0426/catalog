# About

This Item Catalog project is an application where user's can add, edit and delete their own catalog item by signing in using their google account. 

## Getting Started

First, you need to install the following software:

* [VirtualBox](https://www.virtualbox.org/)
* [Vagrant](https://www.vagrantup.com/)

Once you installed the softwares, you need to download and unzip **fullstack.zip**. This will create new directory on your download folder called **fullstack**. Inside of this directory you find another directory called **vagrant**.

Bring the Virtual Machine online:

```sh
$ cd Downloads/fullstack/vagrant
$ vagrant up
$ vagrant ssh
```

Once vagrant is up change the directory to **catalog**:

```sh
vagrant@vagrant:~$ cd /vagrant
vagrant@vagrant:/vagrant$ cd catalog
```

And then, run the **catalog_project.py**:

```sh
vagrant@vagrant:/vagrant/catalog$ python catalog_project.py
```
## Accessing the Web Application

To view the app just open your browser and then type on the address bar **http://localhost:8000**

## Add, Edit or Delete

First, you need to click **Login** on te upper right window and used your gmail account to signin.

To add, edit or delete a Catalog:

   * To add a new catalog just click **Add Catalog**
   * To edit your catalog just click **Edit** below the catalog you created 
   * To delete your catalog just click **Delete** below the catalog you created

To add, edit or delete a Catalog Item:

   * To add a new Catalog Item just click the catalog you created and then click **Add New Item**
   * To edit an Item just click **Edit** below the item you created
   * To delete an Item just click **Delete** below the item you created

## Logout

To logout just click **Logout** on the upper right window.

---
## Description
> This project is all about building a web application using python framework Flask where you can create, read, update and delete the application along with implementing third-party OAuth authenticaton to properly secured your web application.