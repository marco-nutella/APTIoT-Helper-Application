import flet as ft
from src.ivsscalculator import IVSSMainTab
from src.idsescalculator import IDSESMainTab


def main(page: ft.Page):
    counter = ft.Text("0", size=50, data=0)

    ivss_tab = IVSSMainTab(page)
    idses_tab = IDSESMainTab(page)

    selection_tabs = ft.Tabs(
        length=4,
        expand=True,
        content=ft.Column(
            expand=True,
            controls=[
                ft.TabBar(
                    tabs=[
                        ft.Tab(label="IVSS Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="IDSES Calculator", icon=ft.Icons.SETTINGS),
                        ft.Tab(label="Penetration Testing Assistant", icon=ft.Icons.SETTINGS),
                    ]
                ),
                ft.TabBarView(
                    expand=True,
                    controls=[
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=ivss_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=idses_tab.populate(),
                        ),
                        ft.Container(
                            alignment=ft.Alignment.CENTER,
                            content=ft.Text("Settings content"),
                        ),
                    ],
                ),
            ],
        )
    )
    

    page.add(
        ft.SafeArea(
            expand=True,
            content=ft.Container(
                content=selection_tabs,
                alignment=ft.Alignment.CENTER,
            ),
        )
    )



if __name__ == "__main__":
    ft.run(main, assets_dir="assets")
