import flet as ft
from ivss.ivsscalculator import IVSSMainTab
from idses.idsescalculator import IDSESMainTab
from pt.ptassistant import PTAssistantMainTab
from pt.envsetup import EnvSetupView
from pt.intelgathering import IntelGatheringView
from pt.trafficanalysis import TrafficAnalysisView


def main(page: ft.Page):
    ivss_tab = IVSSMainTab(page)
    idses_tab = IDSESMainTab(page)
    pt_assistant = PTAssistantMainTab(page)
    envsetup_view = EnvSetupView(page)
    intelgathering_view = IntelGatheringView(page)
    trafficanalysis_view = TrafficAnalysisView(page)

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
                            content=pt_assistant.populate(),
                        ),
                    ],
                ),
            ],
        )
    )
    

    #page.add(
    #    ft.SafeArea(
    #        expand=True,
    #        content=ft.Container(
    #            content=selection_tabs,
    #            alignment=ft.Alignment.CENTER,
    #        ),
    #    )
    #)

    def route_change():
        page.views.clear()
        page.views.append(
            ft.View(
                route="/",
                controls=[
                    ft.SafeArea(
                        expand=True,
                        content=ft.Container(
                            content=selection_tabs,
                            alignment=ft.Alignment.CENTER,
                        ),
                    )
                ]
            )
        )
        if page.route == "/envsetup":
            page.views.append(
                ft.View(
                    route="/envsetup",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = envsetup_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/intelgathering":
            page.views.append(
                ft.View(
                    route="/intelgathering",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = intelgathering_view.populate()
                        )
                    ]
                )
            )
        if page.route == "/trafficanalysis":
            page.views.append(
                ft.View(
                    route="/trafficanalysis",
                    controls=[
                        ft.SafeArea(
                            expand = True,
                            content = trafficanalysis_view.populate()
                        )
                    ]
                )
            )
        page.update()

    async def view_pop(e):
        if e.view is not None:
            print("View pop:", e.view)
            page.views.remove(e.view)
            top_view = page.views[-1]
            await page.push_route(top_view.route)

    route_change()
    #page.navigate("/envsetup")

    page.on_route_change = route_change
    page.on_view_pop = view_pop


if __name__ == "__main__":
    ft.run(main, assets_dir="assets")
